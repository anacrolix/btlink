package main

import (
	"github.com/anacrolix/generics"
	"github.com/anacrolix/torrent/metainfo"
	qt "github.com/frankban/quicktest"
	"net/url"
	"testing"
)

func TestRedirectOldDomain(t *testing.T) {
	c := qt.New(t)
	test := func(host string, expected generics.Option[string]) {
		c.Check(redirectOldBtRoot(host), qt.Equals, expected)
	}
	test(
		"bt.btlink.anacrolix.link",
		generics.Some("btlink.anacrolix.link"),
	)
	test(
		"hello.ih.bt.btlink.anacrolix.link",
		generics.Some("hello-ih.btlink.anacrolix.link"),
	)
	test(
		"hello.ih.bt.btlink.anacrolix.link",
		generics.Some("hello-ih.btlink.anacrolix.link"),
	)
	test(
		"cast.hello.pk.bt.btlink.anacrolix.link",
		generics.Some("cast.hello-pk.btlink.anacrolix.link"),
	)
	test(
		"cast.hello.pk.bt",
		generics.Some("cast.hello-pk.btlink"),
	)
}

func TestAddGatewayWebseedScheme(t *testing.T) {
	m := metainfo.Magnet{
		Params: make(url.Values),
	}
	addGatewayWebseedToMagnet(&m, "9a0df2a4500d65ab0b58e4ad3ef7c55576ca88f1-ih.btlink.localhost:42080", "http", &url.URL{
		Path:     "/",
		RawQuery: "btlink-no-autoindex",
	})
	qt.Assert(t, m.Params["ws"], qt.DeepEquals, []string{"http://9a0df2a4500d65ab0b58e4ad3ef7c55576ca88f1-ih.btlink.localhost:42080/"})
}
