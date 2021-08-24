# btlink

btlink exposes a HTTP(s) addressing scheme for BitTorrent.

## Architecture

### Domain schema

Where possible, separate domains are used to reference different torrents to provide [origin isolation].

[origin isolation]: https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy

#### {infohash}.ih.bt/{[torrent path schema](#torrent-path-schema)}}

Files within a torrent are exposed via the URL path being the path components of the files join with `/`. Suitable headers may be included as determined. How is the info name field handled? Perhaps it is ignored, except for single-file torrents?
    
#### {salt}.{public key}.pk.bt/{[torrent path schema](#torrent-path-schema)}}

Serves torrent corresponding to lookup of mutable DHT item. Salt is optional per [BEP 46]. This means that owners of a public key can also manage cookies for their salted subdomains (and potentially other resources that support a subdomain relationship like this).

#### {target}.44.bt
Fetches an immutable item from the DHT. 44 is a reference to [BEP 44]. The returned item is an encoded bencode value. Various path and query values might support conversion into other formats.

[BEP 44]: http://bittorrent.org/beps/bep_0044.html
[BEP 46]: http://bittorrent.org/beps/bep_0046.html

### Path schema

#### Torrent path schema

Files within a torrent are exposed with a path equal to the components of the `path` list in the `info` `files` field joined with `/`. There may be additional special paths exposed within at `/.btlink/` and `/.well-known/` as found appropriate.

## Link Records

Domains may link/alias into the `.bt` address scheme by use of a `_btlink` DNS record on the linked domain. For example `chromecast.link` might be hosted on btlink, by way of a `_btlink.chromecast.link` TXT record. The `_btlink` record contains a [magnet link] (or just the btlink domain) where the content will be found.

If a link record exists, it is possible to CNAME or ALIAS the parent domain to a btlink gateway to allow use by non-proxy-using clients.

### Magnet links

Per [BEP 46], `magnet:?xs=urn:btpk:[ Public Key (Hex) ]&s=[ Salt (Hex) ]`, corresponding to the `.pk.bt` domain space.

Regular BitTorrent magnet links correspond to the `.ih.bt` domain space.

## Infrastructure

Here proxies and gateways are described separately, but it's likely that in initial implementations they will be combined. There could be good reasons to separate them for more advanced use.

### Proxies

HTTP proxies can be used to transparently provide the address mapping without modifying HTTP client software. Support for configuring HTTP proxies is well supported and common due to ubiquitous use on corporate and government systems, as well as by anti-censorship and privacy advocates.

Proxies route `.bt` and domains with `_btlink` records to a gateway. They may expose endpoints serving PAC files for trivial end-user configuration.

[PAC]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_PAC_file

### Gateways

Gateways are HTTP servers that serve according to the [Addressing schema](#addressing-schema). They will also intercept requests to domains with `_btlink` records and serve those via BitTorrent if possible.
