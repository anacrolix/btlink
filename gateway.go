package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

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
	updated  time.Time
	updating bool
	payload  krpc.Bep46Payload
}

type handler struct {
	dirPageTemplate      *template.Template
	confluence           confluenceHandler
	dhtItemCache         *ristretto.Cache
	dhtItemCacheGetDedup singleflight.Group
	dhtGetDedup          singleflight.Group
	infoCache            *ristretto.Cache
}

func reverse(ss []string) {
	for i := 0; i < len(ss)/2; i++ {
		j := len(ss) - i - 1
		ss[i], ss[j] = ss[j], ss[i]
	}
}

func (h *handler) serveBtLink(w http.ResponseWriter, r *http.Request) bool {
	log.Printf("considering %q for btlink handling", r.Host)
	ss := strings.Split(r.Host, ".")
	reverse(ss)
	// Strip potential gateway labels
	for len(ss) != 0 && ss[0] != rootDomain {
		ss = ss[1:]
	}
	// The root domain was not seen
	if len(ss) == 0 {
		return false
	}
	log.Printf("handling btlink request for %q", requestUrl(r))
	// Strip the root domain
	ss = ss[1:]
	if len(ss) == 0 {
		http.Error(w, "not implemented yet", http.StatusNotImplemented)
		return true
	}
	switch ss[0] {
	case "ih":
		ss = ss[1:]
		reverse(ss)
		h.serveTorrentPath(w, r, strings.Join(ss, "."))
		return true
	case "pk":
		ss = ss[1:]
		var salt, pk []byte
		switch len(ss) {
		case 2:
			salt = []byte(ss[1])
			fallthrough
		case 1:
			var err error
			pk, err = base36.DecodeString(ss[0])
			if err != nil {
				http.Error(w, fmt.Errorf("error decoding public key from base36: %w", err).Error(), http.StatusBadRequest)
				return true
			}
		default:
			http.Error(w, "bad host", http.StatusBadRequest)
			return true
		}
		target := bep44.MakeMutableTarget(*(*[32]byte)(pk), salt)
		log.Printf("looking up infohash for %q at %x", r.Host, target)
		bep46, err := h.getMutableInfohash(target, string(salt))
		if err != nil {
			log.Printf("error resolving %q: %v", r.Host, err)
			http.Error(w, err.Error(), http.StatusNotFound)
			return true
		}
		log.Printf("resolved %q to %x", r.Host, bep46.Ih)
		h.serveTorrentPath(w, r, hex.EncodeToString(bep46.Ih[:]))
		return true
	}
	panic("unimplemented")
}

func (h *handler) getTorrentInfo(w http.ResponseWriter, r *http.Request, ihHex string) (info metainfo.Info, ok bool) {
	cacheVal, ok := h.infoCache.Get(ihHex)
	if ok {
		info = cacheVal.(metainfo.Info)
		return
	}
	resp, err := h.confluence.do(r.Context(), "/info", url.Values{"ih": {ihHex}})
	if err != nil {
		log.Printf("error getting info from confluence [ih: %q]: %v", ihHex, err)
		http.Error(w, "error getting torrent info", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	err = bencode.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		log.Printf("error decoding info: %v", err)
		http.Error(w, "error decoding torrent info", http.StatusBadGateway)
		return
	}
	ok = true
	cost := estimateRecursiveMemoryUse(info)
	log.Printf("store info for %v in cache with estimated cost %v", ihHex, cost)
	h.infoCache.Set(ihHex, info, int64(cost))
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

func (h *handler) serveTorrentDir(w http.ResponseWriter, r *http.Request, ihHex string) {
	info, ok := h.getTorrentInfo(w, r, ihHex)
	if !ok {
		return
	}
	var subFiles []dirPageItem
	autoIndex := !r.URL.Query().Has("btlink-no-autoindex")
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
				h.serveTorrentFile(w, r, ihHex, dp)
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
	w.Header().Set("Content-Type", "text/html")
	h.dirPageTemplate.Execute(w, dirPageData{
		Path:     dirPath,
		Children: children,
	})
}

type dirPageData struct {
	Path     string
	Children []dirPageItem
}

func (h *handler) serveTorrentPath(w http.ResponseWriter, r *http.Request, ihHex string) {
	if strings.HasSuffix(r.URL.Path, "/") {
		h.serveTorrentDir(w, r, ihHex)
		return
	}
	h.serveTorrentFile(w, r, ihHex, r.URL.Path[1:])
}

func (h *handler) serveTorrentFile(w http.ResponseWriter, r *http.Request, ihHex, filePath string) {
	h.confluence.data(w, r, ihHex, filePath)
}

func (h *handler) getMutableInfohash(target bep44.Target, salt string) (_ krpc.Bep46Payload, err error) {
	ret, err, _ := h.dhtItemCacheGetDedup.Do(string(target[:]), func() (interface{}, error) {
		v, ok := h.dhtItemCache.Get(target[:])
		if ok {
			v := v.(*dhtItemCacheValue)
			stale := time.Since(v.updated) >= time.Minute
			if !v.updating && stale {
				log.Printf("initiating async refresh of cached dht item [target=%x]", target)
				v.updating = true
				go h.getMutableInfohashFromDht(target, salt)
			}
			log.Printf("served dht item from cache [target=%x, stale=%v]", target, stale)
			return v.payload, nil
		}
		return h.getMutableInfohashFromDht(target, salt)
	})
	if err != nil {
		return
	}
	return ret.(krpc.Bep46Payload), err
}

func (h *handler) getMutableInfohashFromDht(target bep44.Target, salt string) (_ krpc.Bep46Payload, err error) {
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
		stored := h.dhtItemCache.Set(target[:], &dhtItemCacheValue{
			updated:  time.Now(),
			updating: false,
			payload:  bep46,
		}, 1)
		log.Printf("caching dht item [target=%x, stored=%v]", target, stored)
		return bep46, err
	})
	if err != nil {
		return
	}
	return ret.(krpc.Bep46Payload), err
}
