package main

import (
	"bytes"
	"crypto/tls"
	_ "embed"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"text/template"
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
	err := mainErr()
	if err != nil {
		log.Printf("error in main: %v", err)
	}
}

func handleConnect(w http.ResponseWriter, destAddr string) {
	conn, err := net.Dial("tcp", destAddr)
	if err != nil {
		log.Printf("error dialling %q: %v", destAddr, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()
	rConn, buf, err := w.(http.Hijacker).Hijack()
	if buf.Reader.Buffered() != 0 || buf.Writer.Buffered() != 0 {
		log.Printf("hijacked connection has %v unread and %v unwritten", buf.Reader.Buffered(), buf.Writer.Buffered())
	}
	if err != nil {
		log.Printf("error hijacking connect request: %v", err)
		return
	}
	defer rConn.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(rConn, conn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(conn, rConn)
	}()
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
	cmd := os.Args[1]
	switch cmd {
	case "proxy":
		return proxy(os.Args[2:])
	case "gencert":
		return genCert(os.Args[2:])
	default:
		return fmt.Errorf("unknown command: %q", cmd)
	}
}

//go:embed pac.tmpl
var proxyPacTmpl string

type pacData struct {
	HttpProxy  string
	HttpsProxy string
}

func serveDynamicPac(w http.ResponseWriter, r *http.Request, httpProxyPort string, httpsProxyPort string) (ok bool, err error) {
	if r.URL.Path != "/.btlink/proxy.pac" {
		return
	}
	ok = true
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
	return
}

func requestLogString(r *http.Request) []byte {
	var buf bytes.Buffer
	r.Write(newIndentWriter(&buf, "  "))
	return bytes.TrimSpace(buf.Bytes())
}

type confluenceHandler struct {
	clientCert       tls.Certificate
	confluenceHost   string
	confluenceScheme string
}

func (ch confluenceHandler) data(w http.ResponseWriter, r *http.Request, ih string, path string) {
	(&httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Host = ch.confluenceHost
			r.URL.Scheme = ch.confluenceScheme
			r.URL.Path = "/data"
			r.URL.RawQuery = url.Values{"ih": {ih}, "path": {path}}.Encode()
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{ch.clientCert},
				InsecureSkipVerify: true,
			},
		},
	}).ServeHTTP(w, r)
}

type handler struct {
	confluence confluenceHandler
}

func (h *handler) serveBtLink(w http.ResponseWriter, r *http.Request) bool {
	log.Printf("considering %q for btlink handling", r.Host)
	if !strings.HasSuffix(r.Host, ".bt") {
		return false
	}
	if strings.HasSuffix(r.Host, ".ih.bt") {
		h.confluence.data(w, r, strings.TrimSuffix(r.Host, ".ih.bt"), r.URL.Path[1:])
		return true
	}
	http.Error(w, "not implemented yet", http.StatusNotImplemented)
	return true
}

func proxy(args []string) error {
	confluenceClientCert, err := tls.LoadX509KeyPair("confluence.pem", "confluence.pem")
	if err != nil {
		log.Printf("error loading confluence client cert: %v", err)
	}
	handler := handler{confluenceHandler{
		clientCert:       confluenceClientCert,
		confluenceHost:   args[1],
		confluenceScheme: args[0],
	}}
	httpPort := "42080"
	httpAddr := ":" + httpPort
	httpsAddr := ":44369"
	log.Printf("starting http server at %q", httpAddr)
	serverErrs := make(chan error, 2)
	go func() {
		err := http.ListenAndServe(httpAddr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("received http request:\n%s", requestLogString(r))
			err := func() error {
				if r.Method == http.MethodConnect {
					// We serve TLS by looping back to the HTTPS handler on this host.
					handleConnect(w, "localhost"+httpsAddr)
					return nil
				}
				if handler.serveBtLink(w, r) {
					return nil
				}
				if ok, err := serveDynamicPac(w, r, httpPort, httpsPort); ok {
					return err
				}
				http.NotFound(w, r)
				return nil
			}()
			if err != nil {
				log.Printf("error in http server handler: %v", err)
			}
		}))
		log.Printf("http server returned: %v", err)
		serverErrs <- err
	}()
	go func() {
		s := http.Server{
			Addr: httpsAddr,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				log.Printf("received request over tls:\n%s", requestLogString(r))
				err := func() error {
					// Connect can be passed to a HTTPS proxy endpoint. We want to handle this
					// ourselves, so we loop it back too.
					if r.Method == http.MethodConnect {
						// We serve TLS by looping back to the HTTPS handler on this host.
						handleConnect(w, "localhost"+httpsAddr)
						return nil
					}
					if handler.serveBtLink(w, r) {
						return nil
					}
					if ok, err := serveDynamicPac(w, r, httpPort, httpsPort); ok {
						return err
					}
					http.NotFound(w, r)
					return nil
				}()
				if err != nil {
					log.Printf("error in https server handler: %v", err)
				}
			}),
			TLSConfig: &tls.Config{
				GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
					cert, err := tls.LoadX509KeyPair(info.ServerName+".pem", "ca.key")
					if err == nil {
						return &cert, nil
					}
					log.Printf("error getting certificate for %q: %v", info.ServerName, err)
					cert, err = tls.LoadX509KeyPair("ca.pem", "ca.key")
					return &cert, err
				},
			},
		}
		log.Printf("starting https server at %q", s.Addr)
		err := s.ListenAndServeTLS("ca.pem", "ca.key")
		log.Printf("https server returned: %v", err)
		serverErrs <- err
	}()
	return fmt.Errorf("server error: %w", <-serverErrs)
}
