import dns.rdatatype
from typing import Tuple

def string_to_request_type(tp: str) -> Tuple[int, Exception | None]:
    tp = tp.strip().upper()
    if tp == "A":
        rt = dns.rdatatype.A
    elif tp == "NS":
        rt = dns.rdatatype.NS
    elif tp == "CNAME":
        rt = dns.rdatatype.CNAME
    elif tp == "SOA":
        rt = dns.rdatatype.SOA
    elif tp == "PTR":
        rt = dns.rdatatype.PTR
    elif tp == "ANY":
        rt = dns.rdatatype.ANY
    elif tp == "MX":
        rt = dns.rdatatype.MX
    elif tp == "TXT":
        rt = dns.rdatatype.TXT
    elif tp == "SRV":
        rt = dns.rdatatype.SRV
    elif tp == "AAAA":
        rt = dns.rdatatype.AAAA
    else:
        rt = dns.rdatatype.NONE
        return rt, ValueError("incorrect type")
    return rt, None