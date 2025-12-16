import threading
from queue import Queue
import json
import os
import time
from datetime import timedelta
from colorama import Fore, init
import shelve
from ratelimit import RateLimiter
import logging
from dnsx.dnsx import DNSX, DNSData, ResponseData, AsnResponse, TraceData, AXFRData
from runner.options import Options as RunnerOptions
from runner.util import lines_in_file, prepare_resolver, fmt_duration, STDIN_MARKER, COMMA, NEW_LINE
from runner.wildcard import is_wildcard
import pyasn
import mapcidr  # فرض بر custom or ipaddress for CIDR
import asn  # custom for ASN

class Runner:
    def __init__(self, options: RunnerOptions):
        self.options = options
        self.dnsx = None
        self.wg_output_worker = threading.Barrier(1)  # use Barrier or Event for wait
        self.wg_resolve_workers = []
        self.wg_wildcard_worker = threading.Barrier(1)
        self.worker_chan = Queue()
        self.output_chan = Queue()
        self.wildcard_worker_chan = Queue()
        self.wildcards = {}  # sync with lock
        self.wildcards_lock = threading.Lock()
        self.wildcards_cache = {}
        self.wildcards_cache_mutex = threading.Lock()
        self.limiter = RateLimiter(max_calls=options.rate_limit, time_frame=1) if options.rate_limit > 0 else None
        self.hm = shelve.open("temp_hmap.db")
        self.stats = CustomStats() if options.show_statistics else None  # custom class for stats
        self.tmp_stdin_file = ""
        self.aurora = Fore

        # init dnsx
        dnsx_opts = dnsx.default_options
        dnsx_opts.max_retries = options.retries
        dnsx_opts.trace_max_recursion = options.trace_max_recursion
        dnsx_opts.hostsfile = options.hosts_file
        dnsx_opts.output_cdn = options.output_cdn
        dnsx_opts.proxy = options.proxy
        dnsx_opts.timeout = options.timeout
        if options.resolvers != "":
            dnsx_opts.base_resolvers = []
            if os.path.exists(options.resolvers):
                dnsx_opts.base_resolvers = [prepare_resolver(rr) for rr in lines_in_file(options.resolvers)]
            else:
                dnsx_opts.base_resolvers = [prepare_resolver(rr) for rr in options.resolvers.split(",")]
        question_types = []
        if options.a:
            question_types.append(dns.rdatatype.A)
        if options.aaaa:
            question_types.append(dns.rdatatype.AAAA)
        if options.cname:
            question_types.append(dns.rdatatype.CNAME)
        if options.ptr:
            question_types.append(dns.rdatatype.PTR)
        if options.soa:
            question_types.append(dns.rdatatype.SOA)
        if options.any:
            question_types.append(dns.rdatatype.ANY)
        if options.txt:
            question_types.append(dns.rdatatype.TXT)
        if options.srv:
            question_types.append(dns.rdatatype.SRV)
        if options.mx:
            question_types.append(dns.rdatatype.MX)
        if options.ns:
            question_types.append(dns.rdatatype.NS)
        if options.caa:
            question_types.append(dns.rdatatype.CAA)
        if len(question_types) == 0 or options.wildcard_domain != "":
            options.a = True
            question_types.append(dns.rdatatype.A)
        dnsx_opts.question_types = question_types
        dnsx_opts.query_all = options.query_all
        dnsx_opts.trace = options.trace
        self.dnsx, err = dnsx.DNSX.new(dnsx_opts)
        if err:
            raise err

        self.wg_output_worker = threading.Event()
        self.wg_wildcard_worker = threading.Event()

        # start workers
        for _ in range(options.threads):
            t = threading.Thread(target=self.resolve_worker)
            t.start()
            self.wg_resolve_workers.append(t)

        threading.Thread(target=self.output_worker).start()

        if options.wildcard_domain != "":
            threading.Thread(target=self.wildcard_worker).start()

        if options.show_statistics:
            self.stats = CustomStats()  # implement custom

    def run(self) -> Exception | None:
        err = self.prepare_input()
        if err is not None:
            return err

        if self.options.stream:
            self.input_worker_stream()
        else:
            self.input_worker()

        # wait resolve
        for _ in range(self.options.threads):
            self.worker_chan.put(None)
        for t in self.wg_resolve_workers:
            t.join()

        # wait wildcard
        if self.options.wildcard_domain != "":
            self.wildcard_worker_chan.put(None)

        # wait output
        self.output_chan.put(None)

        return None

    def prepare_input(self) -> Exception | None:
        has_stdin = not os.isatty(0)
        if has_stdin:
            self.tmp_stdin_file = "temp_stdin.txt"  # temp file
            with open(self.tmp_stdin_file, 'w') as f:
                f.write(sys.stdin.read())
            # defer remove

        data_domains = None
        sc = None

        if self.options.domains != "":
            data_domains = self.pre_process_argument(self.options.domains)
        if sc is None:
            if os.path.exists(self.options.hosts):
                sc = lines_in_file(self.options.hosts)
            elif argument_has_stdin(self.options.hosts) or has_stdin:
                sc = lines_in_file(self.tmp_stdin_file)
            else:
                return ValueError("hosts file or stdin not provided")

        num_hosts = 0
        for item in sc:
            item = item.strip()
            hosts = []
            if "FUZZ" in item:
                fuzz = self.pre_process_argument(self.options.word_list)
                for r in fuzz:
                    subdomain = item.replace("FUZZ", r)
                    hosts.append(subdomain)
            elif self.options.word_list != "":
                prefixes = self.pre_process_argument(self.options.word_list)
                for prefix in prefixes:
                    subdomain = prefix.strip() + "." + item
                    hosts.append(subdomain)
            elif iputil.is_cidr(item):
                # use ipaddress for CIDR
                net = ipaddress.IPv4Network(item)
                for ip in net.hosts():
                    hosts.append(str(ip))
            elif asn.is_asn(item):
                # use pyasn for ASN
                asndb = pyasn.pyasn('ipasn.dat')  # assume data file
                _, prefixes = asndb.lookup_asn(item)
                for prefix in prefixes:
                    net = ipaddress.IPv4Network(prefix)
                    for ip in net.hosts():
                        hosts.append(str(ip))
            else:
                hosts = [item]

            for host in hosts:
                if host in self.hm:
                    continue
                num_hosts += 1
                self.hm[host] = b''

        if self.options.show_statistics:
            # set stats
            pass

        return None

    def pre_process_argument(self, arg: str) -> List[str]:
        if os.path.exists(arg):
            return lines_in_file(arg)
        elif argument_has_stdin(arg):
            return lines_in_file(self.tmp_stdin_file)
        elif arg != "":
            data = arg.replace(COMMA, NEW_LINE)
            return data.splitlines()
        else:
            raise ValueError("empty argument")

    def input_worker_stream(self):
        # similar to prepare_input but stream
        # ...
        pass

    def input_worker(self):
        for key in self.hm:
            if self.options.resume_cfg:
                # resume logic
                pass
            self.worker_chan.put(key)

    def output_worker(self):
        with open(self.options.output_file, 'a') as f  if self.options.output_file else None as f:
            while True:
                out = self.output_chan.get()
                if out is None:
                    break
                print(out)
                if f:
                    f.write(out + '\n')

    def resolve_worker(self):
        while True:
            host = self.worker_chan.get()
            if host is None:
                break
            if self.limiter:
                with self.limiter:
                    self.process_host(host)
            else:
                self.process_host(host)

    def process_host(self, host: str):
        # full logic from Go
        if self.options.axfr:
            axfr_data, err = self.dnsx.axfr(host)
            if err is not None:
                self.output_response_code(host, dns.rcode.REFUSED)
                return
            # process AXFR
            self.output_chan.put(str(axfr_data))
            return

        if self.options.trace:
            trace_data, err = self.dnsx.trace(host)
            if err is not None:
                self.output_response_code(host, dns.rcode.SERVFAIL)
                return
            # process trace
            self.output_chan.put(str(trace_data))
            return

        if len(self.options.question_types) == 1:
            dns_data, err = self.dnsx.query_one(host)
        else:
            dns_data, err = self.dnsx.query_multiple(host)

        if err is not None:
            self.output_response_code(host, dns.rcode.SERVFAIL)
            return

        if dns_data.dns_data.status_code != dns.rcode.NOERROR:
            self.output_response_code(host, dns_data.dns_data.status_code)
            return

        if self.options.has_r_codes:
            if dns_data.dns_data.status_code not in self.options.rcodes:
                return

        if self.options.response_type_filter != "":
            if self.should_skip_record(dns_data.dns_data):
                return

        if self.options.wildcard_domain != "":
            self.wildcard_worker_chan.put(host)
            if host in self.wildcards:
                return

        if self.options.asn:
            # use pyasn
            asndb = pyasn.pyasn('ipasn.dat')
            asn_num, prefix = asndb.lookup(host)
            asn_resp = AsnResponse()
            asn_resp.as_number = asn_num
            # get name, country from API or data
            dns_data.asn = asn_resp

        self.output(host, dns_data)

    def output(self, domain: str, dns_data: ResponseData):
        if self.options.json:
            json_data, err = dns_data.json(without_all_records())
            if err is not None:
                logging.warning(f"Could not marshal json data for {domain}: {err}")
            self.output_chan.put(json_data)
            return

        if self.options.raw:
            self.output_chan.put(dns_data.dns_data.raw_resp)
            return

        if self.options.has_r_codes:
            self.output_response_code(domain, dns_data.dns_data.status_code)
            return

        cdn_name = dns_data.cdn_name
        asn_str = dns_data.asn.__str__() if dns_data.asn else ""
        details = ""
        if cdn_name:
            details += f" [{cdn_name}]"
        if asn_str:
            details += f" {asn_str}"

        if self.options.response_only:
            # output all records
            for record in dns_data.dns_data.all_records:
                self.output_chan.put(f"{record}{details}")
            return

        if self.options.response:
            # output with domain and type
            if self.options.a:
                for a in dns_data.dns_data.A:
                    self.output_chan.put(f"{domain} [A] [{a}] {details}")
            # similar for all types
            return

        # default: just domain
        self.output_chan.put(domain + details)

    def output_response_code(self, domain: str, response_code: int):
        code_str = dns.rcode.to_text(response_code)
        self.output_chan.put(f"{domain} [{code_str}]")

    def should_skip_record(self, dns_data: DNSData) -> bool:
        for et in self.options.response_type_filter_map:
            if et == "a" and dns_data.A:
                return True
            # similar for all
        return False

    def wildcard_worker(self):
        while True:
            host = self.wildcard_worker_chan.get()
            if host is None:
                break
            if self.is_wildcard(host):
                with self.wildcards_lock:
                    self.wildcards[host] = True

    def close(self):
        self.hm.close()
        if self.tmp_stdin_file:
            os.remove(self.tmp_stdin_file)

# custom stats class
class CustomStats:
    def __init__(self):
        self.data = {}
        # implement counters, etc.

    # all methods

def argument_has_stdin(arg: str) -> bool:
    return arg == STDIN_MARKER