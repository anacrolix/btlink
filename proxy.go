package main

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
)

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

//go:embed pac.tmpl
var proxyPacTmpl string

type pacData struct {
	HttpProxy  string
	HttpsProxy string
	RootDomain string
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
		RootDomain: "." + rootDomain,
	})
	if err != nil {
		err = fmt.Errorf("executing template: %w", err)
	}
	return err
}
