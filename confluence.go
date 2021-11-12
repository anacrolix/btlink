package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
)

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
