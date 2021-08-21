function FindProxyForURL(url, host) {
  if (
    dnsDomainIs(host, "chromecast.link")
  ) {
    return "PROXY localhost:42070";
  } else {
    return "DIRECT";
  }
}
