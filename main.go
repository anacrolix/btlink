package main

import (
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/anacrolix/args"
	"github.com/anacrolix/dht/v2/bep44"
	"github.com/anacrolix/dht/v2/krpc"
	"github.com/anacrolix/envpprof"
	"github.com/anacrolix/torrent/bencode"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/dgraph-io/ristretto"
	"github.com/multiformats/go-base36"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/singleflight"
)

type indentWriter struct {
	w       io.Writer
	newLine bool
	indent  []byte
}

func newIndentWriter(w io.Writer, indent string) io.Writer {
	return &indentWriter{w, true, []byte(indent)}
}

func (me *indentWriter) Write(p []byte) (n int, err error) {
	for len(p) != 0 {
		if me.newLine {
			_, err = me.w.Write(me.indent)
			// We intentionally do not include the inserted indent in the return count due to the
			// io.Writer contract.
			if err != nil {
				return
			}
			me.newLine = false
		}
		var nn int
		nn, err = me.w.Write(p[:1])
		n += nn
		if err != nil {
			return
		}
		if p[0] == '\n' {
			me.newLine = true
		}
		p = p[1:]
	}
	return
}

func main() {
	defer envpprof.Stop()
	err := mainErr()
	if err != nil {
		log.Printf("error in main: %v", err)
	}
}

func handleConnect(w http.ResponseWriter, destAddr string, r *http.Request) {
	r.Body.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("can't hijack response writer %v", w)
		// Probably tried over HTTP2, dumbass browsers...
		http.Error(w, "can't hijack response writer", http.StatusBadRequest)
		return
	}
	conn, err := net.Dial("tcp", destAddr)
	if err != nil {
		log.Printf("error dialling %q: %v", destAddr, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	rConn, buf, err := hijacker.Hijack()
	if err != nil {
		log.Printf("error hijacking connect response: %v", err)
		http.Error(w, "error hijacking response writer: %v", http.StatusServiceUnavailable)
		return
	}
	defer rConn.Close()
	if buf.Reader.Buffered() != 0 || buf.Writer.Buffered() != 0 {
		log.Printf("hijacked connection has %v unread and %v unwritten", buf.Reader.Buffered(), buf.Writer.Buffered())
	}
	rConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	var wg sync.WaitGroup
	wg.Add(2)
	copyErrs := make(chan error, 2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(rConn, conn)
		if err != nil {
			log.Printf("error copying from origin to proxy client: %v", err)
		}
		copyErrs <- err
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(conn, rConn)
		if err != nil {
			log.Printf("error copying from proxy client to origin: %v", err)
		}
		copyErrs <- err
	}()
	//<-copyErrs
	wg.Wait()
}

func reverseProxy(w http.ResponseWriter, r *http.Request) {
	(&httputil.ReverseProxy{
		Director: func(r *http.Request) {
			log.Printf("directing request for %v", r.URL)
			r.URL.Scheme = "https"
			r.URL.Host = r.Host
		},
	}).ServeHTTP(w, r)
}

func mainErr() error {
	args.ParseMain(
		args.Subcommand("proxy", proxy),
		args.Subcommand("gencert", genCert),
		args.Subcommand("convert", func(ctx args.SubCmdCtx) (err error) {
			var input string
			decoderChoice := args.Choice{
				Long: "from",
				Choices: map[string]interface{}{
					"hex":       hex.DecodeString,
					"base36":    base36.DecodeString,
					"base32hex": base32.HexEncoding.DecodeString,
				},
				Default: "hex",
			}
			encoderChoice := args.Choice{
				Long: "to",
				Choices: map[string]interface{}{
					"base64url": base64.URLEncoding.EncodeToString,
					"base36lc":  base36.EncodeToStringLc,
					"base32hex": base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString,
					"hex":       hex.EncodeToString,
				},
			}
			ctx.Parse(
				args.Pos("input", &input),
				decoderChoice.ToParam(),
				encoderChoice.ToParam())
			b, err := decoderChoice.SelectedValue().(func(string) ([]byte, error))(input)
			if err != nil {
				return fmt.Errorf("error decoding input: %w", err)
			}
			fmt.Println(encoderChoice.SelectedValue().(func([]byte) string)(b))
			return nil
		}),
	)
	return nil
}

//go:embed pac.tmpl
var proxyPacTmpl string

type pacData struct {
	HttpProxy  string
	HttpsProxy string
}

func serveDynamicPac(w http.ResponseWriter, r *http.Request, httpProxyPort string, httpsProxyPort string) error {
	t := template.Must(template.New("").Parse(proxyPacTmpl))
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	// Chrome seems to ignore the inline, but does pay attention to the filename. It's just nice for
	// end users to be able to view what they're getting remotely.
	w.Header().Set("Content-Disposition", "inline; filename=btlink.pac")
	w.Header().Set("Content-Type", `application/x-ns-proxy-autoconfig`)
	err = t.Execute(w, pacData{
		HttpProxy:  net.JoinHostPort(host, httpProxyPort),
		HttpsProxy: net.JoinHostPort(host, httpsProxyPort),
	})
	if err != nil {
		err = fmt.Errorf("executing template: %w", err)
	}
	return err
}

func requestLogString(r *http.Request) []byte {
	var buf bytes.Buffer
	r.Write(newIndentWriter(&buf, "  "))
	return bytes.TrimRightFunc(buf.Bytes(), unicode.IsSpace)
}

type confluenceHandler struct {
	confluenceHost      string
	confluenceScheme    string
	confluenceTransport http.Transport
}

func (ch *confluenceHandler) data(w http.ResponseWriter, r *http.Request, ih string, path string) {
	(&httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Host = ch.confluenceHost
			r.URL.Scheme = ch.confluenceScheme
			r.URL.Path = "/data"
			r.URL.RawQuery = url.Values{"ih": {ih}, "path": {path}}.Encode()
		},
		Transport: &ch.confluenceTransport,
	}).ServeHTTP(w, r)
}

func (ch *confluenceHandler) do(ctx context.Context, path string, q url.Values) (resp *http.Response, err error) {
	hc := http.Client{
		Transport: &ch.confluenceTransport,
	}
	u := url.URL{
		Scheme:   ch.confluenceScheme,
		Host:     ch.confluenceHost,
		Path:     path,
		RawQuery: q.Encode(),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		panic(err)
	}
	resp, err = hc.Do(req)
	return
}

func (ch *confluenceHandler) dhtGet(ctx context.Context, target, salt string) (b []byte, err error) {
	resp, err := ch.do(ctx, "/bep44", url.Values{"target": {target}, "salt": {salt}})
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected response status code: %v", resp.StatusCode)
		return
	}
	b, err = io.ReadAll(resp.Body)
	return
}

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
	if ss[0] != "bt" {
		return false
	}
	log.Printf("handling .bt request for %q", requestUrl(r))
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
			pk, _ = base36.DecodeString(ss[0])
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
}

func (h *handler) serveTorrentDir(w http.ResponseWriter, r *http.Request, ihHex string) {
	info, ok := h.getTorrentInfo(w, r, ihHex)
	if !ok {
		return
	}
	var subFiles []dirPageItem
	baseDisplayPath := r.URL.Path[1:]
	uniqFiles := make(map[dirPageItem]bool)
	for _, f := range info.UpvertedFiles() {
		dp := f.DisplayPath(&info)
		if strings.HasPrefix(dp, baseDisplayPath) {
			relPath := dp[len(baseDisplayPath):]
			nextSep := strings.Index(relPath, "/")
			if nextSep != -1 {
				relPath = relPath[:nextSep+1]
			}
			item := dirPageItem{
				Href: relPath,
				Name: relPath,
			}
			if !uniqFiles[item] {
				subFiles = append(subFiles, dirPageItem{
					Href: relPath,
					Name: relPath,
				})
			}
			uniqFiles[item] = true
		}
	}
	if len(subFiles) == 0 {
		http.NotFound(w, r)
		return
	}
	if baseDisplayPath != "" {
		subFiles = append([]dirPageItem{
			{"../", "../"},
		}, subFiles...)
	}
	dirPath := r.URL.Path
	w.Header().Set("Content-Type", "text/html")
	h.dirPageTemplate.Execute(w, dirPageData{
		Path:     dirPath,
		Children: subFiles,
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
	h.confluence.data(w, r, ihHex, r.URL.Path[1:])
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

func proxy(scc args.SubCmdCtx) error {
	var confluenceHost, confluenceScheme string
	var httpPortInt, httpsPortInt uint16 = 42080, 44369
	logRequestHeaders := args.Flag(args.FlagOpt{
		Long: "log-request-headers",
	})
	scc.Parse(
		args.Opt(args.OptOpt{
			Long:     "confluence-host",
			Target:   &confluenceHost,
			Short:    'h',
			Required: true,
		}),
		args.Opt(args.OptOpt{
			Long:     "confluence-scheme",
			Target:   &confluenceScheme,
			Short:    's',
			Required: true,
		}),
		args.Opt(args.OptOpt{
			Long:   "http-port",
			Target: &httpPortInt,
		}),
		args.Opt(args.OptOpt{
			Long:   "https-port",
			Target: &httpsPortInt,
		}),
		logRequestHeaders,
	)
	confluenceClientCert, err := tls.LoadX509KeyPair("confluence.pem", "confluence.pem")
	if err != nil {
		log.Printf("error loading confluence client cert: %v", err)
	}
	dhtItemCache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 30,
		// So we can trigger this sooner for testing.
		MaxCost:     3,
		BufferItems: 64,
		// Because we don't represent the cost of cache items using bytes, but ristretto will add
		// the internal cost for the key in bytes.
		IgnoreInternalCost: true,
		OnExit: func(val interface{}) {
			v := val.(*dhtItemCacheValue)
			log.Printf("value removed from dht item cache [item=%v]", v)
		},
	})
	if err != nil {
		return fmt.Errorf("new dht item cache: %w", err)
	}
	infoCache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 10000,
		MaxCost:     50e6,
		BufferItems: 64,
	})
	if err != nil {
		return fmt.Errorf("new info cache: %w", err)
	}
	handler := handler{
		confluence: confluenceHandler{
			confluenceHost:   confluenceHost,
			confluenceScheme: confluenceScheme,
			confluenceTransport: http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates:       []tls.Certificate{confluenceClientCert},
					InsecureSkipVerify: true,
				},
			},
		},
		dhtItemCache: dhtItemCache,
		dirPageTemplate: template.Must(template.New("dir").Parse(`
<pre>
{{ .Path }}$ ls
{{ range .Children -}}
<a href="{{.Href}}">{{.Name}}</a>
{{ end }}
</pre>`,
		)),
		infoCache: infoCache,
	}
	httpPort := strconv.FormatUint(uint64(httpPortInt), 10) // Make the default 42080
	httpAddr := ":" + httpPort
	httpsPort := strconv.FormatUint(uint64(httpsPortInt), 10) // Make sure default is 44369
	httpsAddr := ":" + httpsPort
	proxyMux := http.NewServeMux()
	proxyMux.HandleFunc("/.btlink/proxy.pac", func(w http.ResponseWriter, r *http.Request) {
		err := serveDynamicPac(w, r, httpPort, httpsPort)
		if err != nil {
			log.Printf("error serving dynamic pac: %v", err)
		}
	})
	proxyMux.HandleFunc("/.btlink/rootca.pem", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "ca.pem")
	})
	autocertManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache("autocert-cache"),
		HostPolicy: autocert.HostWhitelist("btlink.anacrolix.link"),
		Email:      "anacrolix+btlink@gmail.com",
	}
	proxyHandler := func(logPrefix string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if logRequestHeaders.Bool() {
				log.Printf("%v: received request\n%s", logPrefix, requestLogString(r))
			}
			err := func() error {
				// Connect can be passed to a HTTPS proxy endpoint. We want to handle this
				// ourselves, so we loop it back too. This also works if we receive CONNECT over HTTPS.
				if r.Method == http.MethodConnect {
					// We serve TLS by looping back to the HTTPS handler on this host.
					log.Printf("handling proxy request for %q", requestUrl(r))
					handleConnect(w, "localhost"+httpsAddr, r)
					return nil
				}
				if handler.serveBtLink(w, r) {
					return nil
				}
				log.Printf("handling proxy request for %q", requestUrl(r))
				proxyMux.ServeHTTP(w, r)
				return nil
			}()
			if err != nil {
				log.Printf("%v: error in proxy handler: %v", logPrefix, err)
			}
		})
	}
	serverErrs := make(chan error, 2)
	go func() {
		log.Printf("starting http server at %q", httpAddr)
		err := http.ListenAndServe(httpAddr, autocertManager.HTTPHandler(proxyHandler("http server")))
		log.Printf("http server returned: %v", err)
		serverErrs <- err
	}()
	go func() {
		var certs []tls.Certificate
		cert, err := tls.LoadX509KeyPair("wildcard.bt.pem", "ca.key")
		if err != nil {
			log.Printf("error loading bt wildcard cert: %v", err)
		} else {
			certs = append(certs, cert)
		}
		cert, err = tls.LoadX509KeyPair("localhost.pem", "ca.key")
		if err != nil {
			log.Printf("error loading localhost cert: %v", err)
		} else {
			certs = append(certs, cert)
		}
		tlsConfig := &tls.Config{
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				for _, cert := range certs {
					if info.SupportsCertificate(&cert) == nil {
						return &cert, nil
					}
				}
				return autocertManager.GetCertificate(info)
			},
		}
		s := http.Server{
			Addr:        httpsAddr,
			Handler:     proxyHandler("tls http server"),
			TLSConfig:   tlsConfig,
			ReadTimeout: 5 * time.Second,
		}
		log.Printf("starting https server at %q", s.Addr)
		err = s.ListenAndServeTLS("", "")
		log.Printf("https server returned: %v", err)
		serverErrs <- err
	}()
	return fmt.Errorf("server error: %w", <-serverErrs)
}

func requestUrl(r *http.Request) string {
	u := *r.URL
	u.Host = r.Host
	u.Scheme = "http"
	if r.TLS != nil {
		u.Scheme = "https"
	}
	return u.String()
}
