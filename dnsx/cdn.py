import socket
import ipaddress
from typing import Tuple

# custom cdncheck: فرض بر لیست rangeها؛ برای کامل، use dict of CDN ranges (from cdncheck lib or manual)
CDN_RANGES = {
    "cloudflare": [ipaddress.IPv4Network("1.1.1.1/32")]  # example, add real ranges
}

class CDNCheck:
    def __init__(self):
        pass

    def check_cdn(self, ip: ipaddress.IPv4Address) -> Tuple[bool, str, None]:
        for name, ranges in CDN_RANGES.items():
            for r in ranges:
                if ip in r:
                    return True, name, None
        return False, "", None

class DNSX:
    def cdn_check(self, domain: str) -> Tuple[bool, str, Exception | None]:
        if self.cdn is None:
            return False, "", ValueError("cdn client not initialized")
        try:
            ips = socket.getaddrinfo(domain, None)
        except socket.gaierror as e:
            return False, "", e
        ipv4_ips = []
        for _, _, _, _, addr in ips:
            try:
                ip = ipaddress.ip_address(addr[0])
                if ip.version == 4:
                    ipv4_ips.append(ip)
            except ValueError:
                pass
        if len(ipv4_ips) < 1:
            return False, "", ValueError(f"no IPV4s found in lookup for {domain}")
        ip_addr = str(ipv4_ips[0])
        try:
            ip = ipaddress.ip_address(ip_addr)
        except ValueError:
            return False, "", ValueError(f"{ip_addr} is not a valid ip")
        return self.cdn.check_cdn(ip)