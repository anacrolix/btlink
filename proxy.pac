function FindProxyForURL(url, host) {
  if (
    dnsDomainIs(host, ".bt")
  ) {
    return "HTTPS localhost:44369; PROXY localhost:42080; DIRECT";
  } else {
    return "DIRECT";
  }
}
