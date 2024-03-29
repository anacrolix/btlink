package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/anacrolix/generics"
	"github.com/davecgh/go-spew/spew"
	"github.com/huandu/xstrings"

	"github.com/anacrolix/dht/v2/bep44"
	"github.com/anacrolix/dht/v2/krpc"
	"github.com/anacrolix/torrent/bencode"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/dgraph-io/ristretto"
	"github.com/dustin/go-humanize"
	"github.com/multiformats/go-base36"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/singleflight"
	"golang.org/x/text/collate"
	"golang.org/x/text/language"
)

type dhtItemCacheValue struct {
	target   bep44.Target
	updated  time.Time
	updating bool
	payload  krpc.Bep46Payload
}

type gatewayHandler struct {
	dirPageTemplate      *template.Template
	confluence           confluenceHandler
	dhtItemCache         *ristretto.Cache
	dhtItemCacheGetDedup singleflight.Group
	dhtGetDedup          singleflight.Group
	metainfoCache        *ristretto.Cache
	gatewayDomains       []string
}

func reverse(ss []string) {
	for i := 0; i < len(ss)/2; i++ {
		j := len(ss) - i - 1
		ss[i], ss[j] = ss[j], ss[i]
	}
}

type gatewayRootPageData struct {
	JustUploaded *uploadedPageData
}

type uploadedPageData struct {
	Infohash   string
	Magnet     template.URL
	GatewayUrl *url.URL
	Debug      string
}

func (h *gatewayHandler) serveRoot(w http.ResponseWriter, r *http.Request) {
	pageData := gatewayRootPageData{}
	if r.Method != http.MethodGet {
		pageData.JustUploaded = h.doUpload(w, r)
	}
	err := htmlTemplates.ExecuteTemplate(w, "gateway-root.html", pageData)
	if err != nil {
		panic(err)
	}
}

func (h *gatewayHandler) doUpload(w http.ResponseWriter, r *http.Request) *uploadedPageData {
	if false {
		err := r.ParseMultipartForm(420)
		if err != nil {
			err = fmt.Errorf("parsing multipart upload form: %w", err)
			log.Print(err)
			http.Error(w, "error parsing multipart form", http.StatusBadRequest)
			return nil
		}
		spew.Fdump(w, r.MultipartForm)
		return nil
	}
	confluenceRequest := h.confluence.newRequest(r.Context(), r.Method, &url.URL{Path: "/upload"}, r.Body)
	for _, h := range []string{"Content-Type", "Content-Length"} {
		confluenceRequest.Header[h] = r.Header[h]
	}
	confluenceResponse, err := h.confluence.do(confluenceRequest)
	if err != nil {
		panic(err)
	}
	defer confluenceResponse.Body.Close()
	if confluenceResponse.StatusCode != http.StatusOK {
		io.Copy(os.Stderr, confluenceResponse.Body)
		panic(confluenceResponse.StatusCode)
	}
	mi, err := metainfo.Load(confluenceResponse.Body)
	if err != nil {
		panic(err)
	}
	ih := mi.HashInfoBytes()
	info, err := mi.UnmarshalInfo()
	if err != nil {
		panic(err)
	}
	var debug bytes.Buffer
	if false {
		spew.Fdump(&debug, info)
	}
	magnet := mi.Magnet(&ih, &info)
	addGatewayWebseedToMagnet(&magnet, infohashHost(ih.HexString(), r.Host), h.gatewayWebseedScheme(r), r.URL)
	templateData := &uploadedPageData{
		ih.HexString(),
		template.URL(magnet.String()),
		&url.URL{
			Scheme: r.URL.Scheme,
			Host:   infohashHost(ih.HexString(), r.Host),
		},
		debug.String(),
	}
	mi.InfoBytes = nil
	if false {
		spew.Fdump(&debug, mi)
	}
	// Confluence immediately imports upload data.
	if false {
		// If the data isn't accessible, the gateway will get stuck trying to load the autoindex if the torrent has one.
		templateData.GatewayUrl.RawQuery = "btlink-no-autoindex"
	}
	return templateData
}

func infohashHost(ihHex, gateway string) string {
	return ihHex + "-ih." + gateway
}

func (h *gatewayHandler) resolveDomainDnsLink(w http.ResponseWriter, r *http.Request) bool {
	name := "_dnslink." + r.Host
	txts, err := net.LookupTXT(name)
	if err != nil {
		err = fmt.Errorf("resolving txt for %v: %w", name, err)
		log.Printf("error %s", err)
		return false
	}
	if len(txts) == 0 {
		return false
	}
	return h.serveBtLinkDomain(w, r, strings.Split(txts[0], "."), generics.None[string]())
}

func (h *gatewayHandler) serveOldBtLinkRedirection(w http.ResponseWriter, r *http.Request) bool {
	log.Printf("considering %q for btlink handling", r.Host)
	newHost := redirectOldBtRoot(r.Host)
	if !newHost.Ok {
		return false
	}
	newUrl := r.URL.ResolveReference(&url.URL{
		Host: newHost.Value,
	})
	http.Redirect(w, r, newUrl.String(), http.StatusTemporaryRedirect)
	return true
}

func (h *gatewayHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) bool {
	if h.serveBtLink(w, r) {
		return true
	}
	if h.serveOldBtLinkRedirection(w, r) {
		return true
	}
	if h.resolveDomainDnsLink(w, r) {
		return true
	}
	return false
}

func (h *gatewayHandler) serveBtLink(w http.ResponseWriter, r *http.Request) bool {
	log.Printf("considering %q for btlink handling", r.Host)
	ss := strings.Split(r.Host, ".")
	reverse(ss)
	gatewayDomainParts := make([]string, 0, len(ss))
	// Strip potential gateway labels
	for len(ss) != 0 && ss[0] != rootDomain {
		gatewayDomainParts = append(gatewayDomainParts, ss[0])
		ss = ss[1:]
	}
	// The root domain was not seen
	if len(ss) == 0 {
		return false
	}
	log.Printf("handling btlink request for %q", requestUrl(r))
	gatewayDomainParts = append(gatewayDomainParts, ss[0])
	// Strip the root domain
	ss = ss[1:]
	reverse(gatewayDomainParts)
	return h.serveBtLinkDomain(w, r, ss, generics.Some(strings.Join(gatewayDomainParts, ".")))
}

func (h *gatewayHandler) serveBtLinkDomain(w http.ResponseWriter, r *http.Request, ss []string, gatewayDomain generics.Option[string]) bool {
	if len(ss) == 0 {
		h.serveRoot(w, r)
		return true
	}
	labelParts := strings.Split(ss[0], "-")
	ss = ss[1:]
	reverse(labelParts)
	switch labelParts[0] {
	case "ih":
		labelParts = labelParts[1:]
		reverse(labelParts)
		if len(labelParts) != 1 {
			http.Error(w, "bad host", http.StatusBadRequest)
			return true
		}
		h.serveTorrentPath(w, r, strings.Join(labelParts, "-"), gatewayDomain)
		return true
	case "pk":
		labelParts = labelParts[1:]
		if len(labelParts) == 0 {
			http.Error(w, "bad host", http.StatusBadRequest)
			return true
		}
		pk, err := base36.DecodeString(labelParts[0])
		if err != nil {
			http.Error(w, fmt.Errorf("error decoding public key from base36: %w", err).Error(), http.StatusBadRequest)
			return true
		}
		labelParts = labelParts[1:]
		reverse(labelParts)
		reverse(ss)
		if len(labelParts) != 0 {
			ss = append(ss, strings.Join(labelParts, "-"))
		}
		salt := strings.Join(ss, ".")
		log.Printf("salt for %q: %q", r.Host, salt)
		target := bep44.MakeMutableTarget(*(*[32]byte)(pk), []byte(salt))
		log.Printf("looking up infohash for %q at %x", r.Host, target)
		bep46, err := h.getMutableInfohash(target, string(salt))
		if err != nil {
			log.Printf("error resolving %q: %v", r.Host, err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return true
		}
		log.Printf("resolved %q to %x", r.Host, bep46.Ih)
		h.serveTorrentPath(w, r, hex.EncodeToString(bep46.Ih[:]), gatewayDomain)
		return true
	}
	http.Error(w, "bad host", http.StatusBadRequest)
	return true
}

func redirectOldBtRoot(host string) (newHost generics.Option[string]) {
	ss := strings.Split(host, ".")
	reverse(ss)
	var gatewayParts []string
	// Strip potential gateway labels
	for len(ss) != 0 && ss[0] != oldRootDomain {
		gatewayParts = append(gatewayParts, ss[0])
		ss = ss[1:]
	}
	// The root domain was not seen
	if len(ss) == 0 {
		return
	}
	if len(gatewayParts) == 0 || gatewayParts[len(gatewayParts)-1] != rootDomain {
		gatewayParts = append(gatewayParts, rootDomain)
	}
	reverse(gatewayParts)
	gateway := strings.Join(gatewayParts, ".")
	// Strip the root domain
	ss = ss[1:]
	if len(ss) == 0 {
		return generics.Some(gateway)
	}
	switch ss[0] {
	case "ih":
		ss = ss[1:]
		reverse(ss)
		return generics.Some(infohashHost(strings.Join(ss, "."), gateway))
	case "pk":
		ss = ss[1:]
		reverse(ss)
		return generics.Some(strings.Join(ss, ".") + "-pk." + gateway)
	}
	return
}

func (h *gatewayHandler) getTorrentMetaInfo(w http.ResponseWriter, r *http.Request, ihHex string) (mi metainfo.MetaInfo, ok bool) {
	cacheVal, ok := h.metainfoCache.Get(ihHex)
	if ok {
		mi = cacheVal.(metainfo.MetaInfo)
		return
	}
	resp, err := h.confluence.get(r.Context(), "/metainfo", url.Values{"ih": {ihHex}})
	if err != nil {
		log.Printf("error getting meta-info from confluence [ih: %q]: %v", ihHex, err)
		http.Error(w, "error getting torrent meta-info", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	err = bencode.NewDecoder(resp.Body).Decode(&mi)
	if err != nil {
		log.Printf("error decoding info: %v", err)
		http.Error(w, "error decoding torrent meta-info", http.StatusBadGateway)
		return
	}
	ok = true
	cost := estimateRecursiveMemoryUse(mi)
	log.Printf("store info for %v in cache with estimated cost %v", ihHex, cost)
	h.metainfoCache.Set(ihHex, mi, int64(cost))
	return
}

func estimateRecursiveMemoryUse(val interface{}) int {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(val)
	if err != nil {
		panic(err)
	}
	return buf.Len()
}

type dirPageItem struct {
	Href string
	Name string
	Size string
}

var torrentFilesCollator = collate.New(language.AmericanEnglish, collate.Numeric, collate.IgnoreCase)

func (h *gatewayHandler) gatewayWebseedScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func requestHasBtlinkQueryFlag(r *http.Request, flag string) bool {
	return r.URL.Query().Has(xstrings.ToKebabCase("btlink " + flag))
}

func (h *gatewayHandler) serveTorrentDir(w http.ResponseWriter, r *http.Request, ihHex string, gatewayDomain generics.Option[string]) {
	mi, ok := h.getTorrentMetaInfo(w, r, ihHex)
	if !ok {
		return
	}
	info, err := mi.UnmarshalInfo()
	if err != nil {
		panic(err)
	}
	var subFiles []dirPageItem
	autoIndex := !requestHasBtlinkQueryFlag(r, "no autoindex")
	baseDisplayPath := r.URL.Path[1:]
	upvertedFiles := info.UpvertedFiles()
	subDirs := make(map[string]int64, len(upvertedFiles))
	for _, f := range upvertedFiles {
		dp := f.DisplayPath(&info)
		if !strings.HasPrefix(dp, baseDisplayPath) {
			continue
		}
		relPath := dp[len(baseDisplayPath):]
		if autoIndex {
			// Serve this file as the directory.
			if relPath == "index.html" {
				h.serveTorrentFile(w, r, ihHex, dp, gatewayDomain)
				return
			}
		}
		nextSep := strings.Index(relPath, "/")
		if nextSep == -1 {
			subFiles = append(subFiles, dirPageItem{
				Href: relPath,
				Name: relPath,
				Size: humanize.Bytes(uint64(f.Length)),
			})
		} else {
			relPath = relPath[:nextSep+1]
			subDirs[relPath] += f.Length
		}
	}
	if len(subDirs) == 0 && len(subFiles) == 0 {
		http.NotFound(w, r)
		return
	}
	children := make([]dirPageItem, 0, 1+len(subDirs)+len(subFiles))
	if baseDisplayPath != "" {
		children = append(children, dirPageItem{"../", "../", ""})
	}
	for relPath, size := range subDirs {
		children = append(children, dirPageItem{
			Href: relPath,
			Name: relPath,
			Size: humanize.Bytes(uint64(size)),
		})
	}
	children = append(children, subFiles...)
	// Dirs come from an unstable source (map), but their names are unique.
	slices.SortStableFunc(children, func(l, r dirPageItem) bool {
		lDir := strings.HasSuffix(l.Name, "/")
		rDir := strings.HasSuffix(r.Name, "/")
		if lDir != rDir {
			return lDir
		}
		i := torrentFilesCollator.CompareString(l.Name, r.Name)
		if i != 0 {
			return i < 0
		}
		return false
	})
	dirPath := r.URL.Path
	infoHash := metainfo.NewHashFromHex(ihHex)
	w.Header().Set("Content-Type", "text/html")
	magnet := mi.Magnet(&infoHash, &info)
	spew.Dump(*r.URL)
	spew.Dump(h.gatewayWebseedScheme(r), magnet)
	addGatewayWebseedToMagnet(&magnet, r.Host, h.gatewayWebseedScheme(r), r.URL)
	h.dirPageTemplate.Execute(w, dirPageData{
		Path:      dirPath,
		Children:  children,
		MagnetURI: template.URL(magnet.String()),
	})
}

func addGatewayWebseedToMagnet(m *metainfo.Magnet, gatewayHost, scheme string, baseUrl *url.URL) {
	ref := url.URL{
		Host: gatewayHost,
		Path: "/",
	}
	if baseUrl.Scheme == "" {
		ref.Scheme = scheme
	}
	m.Params.Add("ws", baseUrl.ResolveReference(&ref).String())
}

type dirPageData struct {
	Path      string
	Children  []dirPageItem
	MagnetURI template.URL
}

func (h *gatewayHandler) serveTorrentPath(w http.ResponseWriter, r *http.Request, ihHex string, gatewayDomain generics.Option[string]) {
	if strings.HasSuffix(r.URL.Path, "/") {
		h.serveTorrentDir(w, r, ihHex, gatewayDomain)
		return
	}
	h.serveTorrentFile(w, r, ihHex, r.URL.Path[1:], gatewayDomain)
}

func (h *gatewayHandler) serveTorrentFile(w http.ResponseWriter, r *http.Request, ihHex, filePath string, gatewayDomain generics.Option[string]) {
	gatewayDomains := h.gatewayDomains
	if gatewayDomain.Ok {
		gatewayDomains = append([]string{gatewayDomain.Value}, gatewayDomains...)
	}
	h.confluence.data(w, r, ihHex, filePath, gatewayDomains)
}

func (h *gatewayHandler) getMutableInfohash(target bep44.Target, salt string) (_ krpc.Bep46Payload, err error) {
	ret, err, _ := h.dhtItemCacheGetDedup.Do(string(target[:]), func() (interface{}, error) {
		v, ok := h.dhtItemCache.Get(target[:])
		if ok {
			v := v.(*dhtItemCacheValue)
			stale := time.Since(v.updated) >= time.Minute
			if !v.updating && stale {
				log.Printf("initiating async refresh of cached dht item [target=%x]", target)
				v.updating = true
				go func() {
					bep46, err := h.getMutableInfohashFromDht(target, salt)
					v.updating = false
					if err != nil {
						log.Printf("error updating dht item cache [target=%x]: %v", target, err)
						return
					}
					h.cacheDhtItem(target, bep46)
				}()
			}
			log.Printf("served dht item from cache [target=%x, stale=%v]", target, stale)
			return v.payload, nil
		}
		bep46, err := h.getMutableInfohashFromDht(target, salt)
		if err == nil {
			h.cacheDhtItem(target, bep46)
		}
		return bep46, err
	})
	if err != nil {
		return
	}
	return ret.(krpc.Bep46Payload), err
}

func (h *gatewayHandler) cacheDhtItem(target bep44.Target, bep46 krpc.Bep46Payload) {
	stored := h.dhtItemCache.Set(target[:], &dhtItemCacheValue{
		updated:  time.Now(),
		updating: false,
		payload:  bep46,
		target:   target,
	}, 1)
	log.Printf("caching dht item [target=%x, stored=%v]", target, stored)
}

func (h *gatewayHandler) getMutableInfohashFromDht(target bep44.Target, salt string) (_ krpc.Bep46Payload, err error) {
	ret, err, _ := h.dhtGetDedup.Do(string(target[:]), func() (_ interface{}, err error) {
		b, err := h.confluence.dhtGet(context.Background(), hex.EncodeToString(target[:]), salt)
		if err != nil {
			err = fmt.Errorf("getting from dht via confluence: %w", err)
			return
		}
		var bep46 krpc.Bep46Payload
		err = bencode.Unmarshal(b, &bep46)
		if err != nil {
			err = fmt.Errorf("unmarshalling bep46 payload from confluence response: %w", err)
			return
		}
		return bep46, err
	})
	if err != nil {
		return
	}
	return ret.(krpc.Bep46Payload), err
}
