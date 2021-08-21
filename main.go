package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"sync"
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
	rConn, _, err := w.(http.Hijacker).Hijack()
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
		return proxy()
	case "gencert":
		return genCert(os.Args[2:])
	default:
		return fmt.Errorf("unknown command: %q", cmd)
	}
}

func proxy() error {
	httpAddr := ":42080"
	httpsAddr := ":44369"
	log.Printf("starting http server at %q", httpAddr)
	serverErrs := make(chan error, 2)
	go func() {
		err := http.ListenAndServe(httpAddr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var buf bytes.Buffer
			r.Write(newIndentWriter(&buf, "  "))
			log.Printf("received http request:\n%s", bytes.TrimSpace(buf.Bytes()))
			if r.Method == http.MethodConnect {
				handleConnect(w, "localhost"+httpsAddr)
				return
			}
			reverseProxy(w, r)
			return
			log.Printf("unhandled method %q", r.Method)
			http.Error(w, fmt.Sprintf("unhandled method %q", r.Method), http.StatusNotImplemented)
		}))
		log.Printf("http server returned: %v", err)
		serverErrs <- err
	}()
	go func() {
		s := http.Server{
			Addr: httpsAddr,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var buf bytes.Buffer
				r.Write(newIndentWriter(&buf, "  "))
				log.Printf("received request over tls:\n%s", bytes.TrimSpace(buf.Bytes()))
				if r.Method == http.MethodConnect {
					handleConnect(w, "localhost:42070")
					return
				}
				reverseProxy(w, r)
				return
				log.Printf("unhandled method %q", r.Method)
				http.Error(w, fmt.Sprintf("unhandled method %q", r.Method), http.StatusNotImplemented)
			}),
			TLSConfig: &tls.Config{
				GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
					log.Printf("getting certificate for %q", info.ServerName)
					cert, err := tls.LoadX509KeyPair(info.ServerName+".pem", "ca.key")
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
