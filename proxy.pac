// This file is for local PAC testing without having to restart the server or execute the dynamic
// PAC template.
function FindProxyForURL(url, host) {
  if (
    dnsDomainIs(host, ".bt")
  ) {
    return "HTTPS localhost:44369";
  } else {
    return "DIRECT";
  }
}
