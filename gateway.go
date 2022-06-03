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
	"golang.org/x/sync/singleflight"
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
	if ss[0] != rootDomain {
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
	Size string
}

func (h *handler) serveTorrentDir(w http.ResponseWriter, r *http.Request, ihHex string) {
	info, ok := h.getTorrentInfo(w, r, ihHex)
	if !ok {
		return
	}
	var subFiles []dirPageItem
	autoIndex := !r.URL.Query().Has("btlink-no-autoindex")
	baseDisplayPath := r.URL.Path[1:]
	uniqFiles := make(map[dirPageItem]bool)
	for _, f := range info.UpvertedFiles() {
		dp := f.DisplayPath(&info)
		if strings.HasPrefix(dp, baseDisplayPath) {
			relPath := dp[len(baseDisplayPath):]
			if autoIndex {
				// Serve this file as the directory.
				if relPath == "index.html" {
					h.serveTorrentFile(w, r, ihHex, dp)
					return
				}
			}
			nextSep := strings.Index(relPath, "/")
			if nextSep != -1 {
				relPath = relPath[:nextSep+1]
			}
			item := dirPageItem{
				Href: relPath,
				Name: relPath,
				Size: humanize.Bytes(uint64(f.Length)),
			}
			if !uniqFiles[item] {
				subFiles = append(subFiles, item)
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
			{"../", "../", ""},
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
