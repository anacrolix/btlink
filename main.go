package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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

func mainErr() error {
	addr := ":42070"
	log.Printf("starting http server at %q", addr)
	return http.ListenAndServe(":42070", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		r.Write(newIndentWriter(&buf, "  "))
		log.Printf("received request:\n%s", buf.Bytes())
		if r.Method == http.MethodConnect {
			conn, err := net.Dial("tcp", r.Host)
			if err != nil {
				log.Printf("error dialling %q: %v", r.Host, err)
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
			return
		}
		log.Printf("unhandled method %q", r.Method)
		http.Error(w, fmt.Sprintf("unhandled method %q", r.Method), http.StatusNotImplemented)
	}))
}
