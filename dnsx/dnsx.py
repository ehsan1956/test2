import json
from typing import List, Tuple, Dict
import time
import dns.resolver
import dns.rdatatype
import dns.zone
import dns.query
import dns.message
import dns.name
from tenacity import retry, stop_after_attempt, wait_fixed
import ipaddress
from .util import string_to_request_type
from .cdn import CDNCheck

class DNSData:
    def __init__(self):
        self.A: List[str] = []
        self.AAAA: List[str] = []
        self.CNAME: List[str] = []
        self.NS: List[str] = []
        self.MX: List[str] = []
        self.SOA: List[Dict] = []  # e.g., {'ns':, 'mbox':, etc.}
        self.TXT: List[str] = []
        self.SRV: List[str] = []
        self.PTR: List[str] = []
        self.CAA: List[str] = []
        self.raw_resp: str = ""
        self.all_records: List[str] = []
        self.status_code: int = 0

class TraceData:
    def __init__(self):
        self.traces: List[Dict] = []

class AXFRData:
    def __init__(self):
        self.records: Dict = {}

class Options:
    def __init__(self):
        self.base_resolvers: List[str] = []
        self.max_retries: int = 0
        self.question_types: List[int] = []
        self.trace: bool = False
        self.trace_max_recursion: int = 0
        self.hostsfile: bool = False
        self.output_cdn: bool = False
        self.query_all: bool = False
        self.proxy: str = ""
        self.timeout: time.timedelta = time.timedelta(seconds=0)

default_options = Options()
default_options.base_resolvers = [
    "udp:1.1.1.1:53", "udp:1.0.0.1:53", "udp:8.8.8.8:53", "udp:8.8.4.4:53",
    "udp:9.9.9.9:53", "udp:149.112.112.112:53", "udp:208.67.222.222:53", "udp:208.67.220.220:53",
]
default_options.max_retries = 5
default_options.question_types = [dns.rdatatype.A]
default_options.trace_max_recursion = 255
default_options.hostsfile = True
default_options.timeout = time.timedelta(seconds=3)

class AsnResponse:
    def __init__(self):
        self.as_number: str = ""
        self.as_name: str = ""
        self.as_country: str = ""
        self.as_range: List[str] = []

    def __str__(self) -> str:
        return f"[{self.as_number}, {self.as_name}, {self.as_country}]"

class ResponseData:
    def __init__(self):
        self.dns_data: DNSData = DNSData()
        self.is_cdn_ip: bool = False
        self.cdn_name: str = ""
        self.asn: AsnResponse | None = None

    def json(self, *options) -> Tuple[str, Exception | None]:
        data_to_marshal = vars(self).copy()
        data_to_marshal.pop('raw_resp', None)
        for opt in options:
            opt(data_to_marshal)
        try:
            return json.dumps(data_to_marshal), None
        except Exception as e:
            return "", e

def without_all_records():
    def func(d: Dict):
        d['all_records'] = None
    return func

class RetryDNS:
    def __init__(self, options: Options):
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [r[r.find(':')+1:].split('//')[-1] if '://' in r else r.split(':')[0] for r in options.base_resolvers]
        self.max_retries = options.max_retries
        self.timeout = options.timeout.total_seconds()
        self.resolver.lifetime = self.timeout
        self.proxy = options.proxy  # if proxy, use dnspython with proxy support or custom
        self.tcp_fallback = True
        self.hostsfile = options.hostsfile  # if True, load /etc/hosts custom

    @retry(stop=stop_after_attempt(5), wait=wait_fixed(1))
    def query(self, hostname: str, qtype: int) -> dns.message.Message:
        try:
            ans = self.resolver.resolve(hostname, rdtype=qtype)
            return ans.response
        except Exception as e:
            if self.tcp_fallback:
                q = dns.message.make_query(hostname, qtype)
                ans = dns.query.tcp(q, self.resolver.nameservers[0])
                return ans
            raise e

    def query_multiple(self, hostname: str, qtypes: List[int]) -> DNSData:
        data = DNSData()
        for qt in qtypes:
            resp = self.query(hostname, qt)
            data.raw_resp += resp.to_text() + "\n"
            for rr in resp.answer:
                if rr.rdtype == dns.rdatatype.A:
                    data.A.append(str(rr[0]))
                elif rr.rdtype == dns.rdatatype.AAAA:
                    data.AAAA.append(str(rr[0]))
                elif rr.rdtype == dns.rdatatype.CNAME:
                    data.CNAME.append(str(rr[0]))
                elif rr.rdtype == dns.rdatatype.NS:
                    data.NS.append(str(rr[0]))
                elif rr.rdtype == dns.rdatatype.MX:
                    data.MX.append(str(rr[0]))
                elif rr.rdtype == dns.rdatatype.SOA:
                    soa = {'ns': str(rr[0].mname), 'mbox': str(rr[0].rname)}
                    data.SOA.append(soa)
                elif rr.rdtype == dns.rdatatype.TXT:
                    data.TXT.append(str(rr[0]))
                elif rr.rdtype == dns.rdatatype.SRV:
                    data.SRV.append(str(rr[0]))
                elif rr.rdtype == dns.rdatatype.PTR:
                    data.PTR.append(str(rr[0]))
                elif rr.rdtype == dns.rdatatype.CAA:
                    data.CAA.append(str(rr[0]))
            data.all_records.extend(data.A + data.AAAA + data.CNAME + data.NS + data.MX + [s['ns'] for s in data.SOA] + data.TXT + data.SRV + data.PTR + data.CAA)
            data.status_code = resp.rcode()
        return data

    def trace(self, hostname: str, qtype: int, max_recursion: int) -> TraceData:
        traces = []
        current_name = dns.name.from_text(hostname)
        recursion = 0
        while recursion < max_recursion:
            q = dns.message.make_query(current_name, qtype)
            resp = dns.query.udp(q, self.resolver.nameservers[0])
            traces.append(resp.to_text())
            if resp.rcode() == dns.rcode.NOERROR:
                break
            # update current_name from authority if delegation
            if resp.authority:
                current_name = dns.name.from_text(str(resp.authority[0][0]))
            recursion += 1
        return TraceData(traces=traces)

    def axfr(self, hostname: str) -> AXFRData:
        try:
            xfr = dns.query.xfr(self.resolver.nameservers[0], hostname)
            zone = dns.zone.from_xfr(xfr)
            records = {str(name): str(rdata) for name, node in zone.nodes.items() for rdata in node.rdatasets[0].items}
            return AXFRData(records=records)
        except Exception as e:
            raise e

    def resolve(self, hostname: str) -> DNSData:
        return self.query_multiple(hostname, [dns.rdatatype.A])

class DNSX:
    def __init__(self, dns_client: RetryDNS, options: Options, cdn: CDNCheck | None):
        self.dns_client = dns_client
        self.options = options
        self.cdn = cdn

    @classmethod
    def new(cls, options: Options) -> Tuple['DNSX', Exception | None]:
        try:
            dns_client = RetryDNS(options)
            dns_client.tcp_fallback = True
            cdn = None
            if options.output_cdn:
                cdn = CDNCheck()
            return cls(dns_client, options, cdn), None
        except Exception as e:
            return None, e

    def lookup(self, hostname: str) -> Tuple[List[str], Exception | None]:
        try:
            ipaddress.ip_address(hostname)
            return [hostname], None
        except ValueError:
            pass

        dnsdata = self.dns_client.resolve(hostname)
        if dnsdata is None or len(dnsdata.A) == 0:
            return [], ValueError("no ips found")
        return dnsdata.A, None

    def query_one(self, hostname: str) -> Tuple[DNSData, Exception | None]:
        if len(self.options.question_types) == 0:
            return None, ValueError("no question types")
        return self.dns_client.query_multiple(hostname, [self.options.question_types[0]])

    def query_multiple(self, hostname: str) -> Tuple[DNSData, Exception | None]:
        filtered_question_types = self.options.question_types[:]
        if self.options.query_all:
            is_ip = bool(ipaddress.ip_address(hostname) if not ipaddress.ip_address(hostname).is_unspecified else False)
            if not is_ip:
                filtered_question_types = [qt for qt in filtered_question_types if qt != dns.rdatatype.PTR]
            else:
                filtered_question_types = [dns.rdatatype.PTR]
        return self.dns_client.query_multiple(hostname, filtered_question_types)

    def trace(self, hostname: str) -> Tuple[TraceData, Exception | None]:
        if len(self.options.question_types) == 0:
            return None, ValueError("no question types specified for trace")
        return self.dns_client.trace(hostname, self.options.question_types[0], self.options.trace_max_recursion)

    def axfr(self, hostname: str) -> Tuple[AXFRData, Exception | None]:
        return self.dns_client.axfr(hostname)