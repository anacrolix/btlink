package main

import (
	"bytes"
	"io"
	"net/http"
	"unicode"
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

func requestLogString(r *http.Request) []byte {
	var buf bytes.Buffer
	r.Write(newIndentWriter(&buf, "  "))
	return bytes.TrimRightFunc(buf.Bytes(), unicode.IsSpace)
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
