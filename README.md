# btlink

btlink introduces a HTTP(s) addressing scheme into BitTorrent.

## Proxies

HTTP proxies can be used to transparently provide the mapping without modifying HTTP client software. Support for configuring HTTP proxies is well supported and common due to ubiquitous use on corporate and government systems, as well as by anti-censorship and privacy advocaetes.

## Addressing schema

Where possible, separate domains are used to reference different torrents to provide [origin isolation].

[origin isolation]: https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy

<dl>
  <dt>{infohash}.ih.bt/{files...}</dt>
  <dd>File path components from the info files are joined with `/`.
  <dt>{salt}.{public key}.pk.bt</dt>
  <dd>Serves torrent corresponding to lookup of mutable DHT item. Salt is optional per BEP 46. This means that owners of a public key can also manage cookies for their salted subdomains (and potentially other resources that support a subdomain relationship like this).
  <dt>{target}.44.bt</dt>
  <dd>Fetches an immutable item from the DHT. 44 is a reference to [BEP 44]. The returned item is an encoded bencode value. Various path and query values might support conversion into other formats.</dd>
</dl>

[BEP 44]: http://bittorrent.org/beps/bep_0044.html

## Link Records

Domains may link/alias into the `.bt` address scheme by use of a `_btlink` record on the linked domain. For example `chromecast.link` might be hosted on btlink, by way of a `_btlink.chromecast.link` TXT record. The `_btlink` record contains a [magnet link] (or just the btlink domain) where the content will be found.

If a link record exists, it is possible to CNAME or ALIAS the parent domain to a btlink gateway to allow use by non-proxy-using clients.

## Gateways

Gateways are HTTP(s) servers that serve according to the [Addressing schema](#addressing-schema). They will follow _btlink records if found, and serve accordingly.

## Proxies

Proxies route `.bt` domains to a gateway.
