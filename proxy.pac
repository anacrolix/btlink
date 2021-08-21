function FindProxyForURL(url, host) {
  if (
    dnsDomainIs(host, "chromecast.link")
  ) {
    return "PROXY localhost:42080";
  } else {
    return "DIRECT";
  }
}
