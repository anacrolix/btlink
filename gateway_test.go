package main

import (
	"github.com/anacrolix/generics"
	qt "github.com/frankban/quicktest"
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
