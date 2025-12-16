import argparse
import sys
import json
import os
from datetime import timedelta
import logging
from colorama import init as colorama_init, Fore
from runner.banner import VERSION, show_banner, get_update_callback, auth_with_pdcp
from runner.resume import ResumeCfg
from runner.healthcheck import do_health_check
from runner.util import lines_in_file, is_url, extract_domain, prepare_resolver, fmt_duration

DEFAULT_RESUME_FILE = "resume.cfg"

PDCP_API_KEY = ""

class Options:
    def __init__(self):
        self.resolvers = ""
        self.hosts = ""
        self.domains = ""
        self.word_list = ""
        self.threads = 100
        self.rate_limit = -1
        self.retries = 2
        self.output_file = ""
        self.raw = False
        self.silent = False
        self.verbose = False
        self.version = False
        self.no_color = False
        self.response = False
        self.response_only = False
        self.a = False
        self.aaaa = False
        self.ns = False
        self.cname = False
        self.ptr = False
        self.mx = False
        self.soa = False
        self.any = False
        self.txt = False
        self.srv = False
        self.axfr = False
        self.caa = False
        self.json = False
        self.omit_raw = False
        self.trace = False
        self.trace_max_recursion = 255
        self.wildcard_threshold = 5
        self.wildcard_domain = ""
        self.show_statistics = False
        self.rcodes = {}
        self.r_code = ""
        self.response_type_filter = ""
        self.response_type_filter_map = []
        self.has_r_codes = False
        self.resume = False
        self.resume_cfg: ResumeCfg | None = None
        self.hosts_file = False
        self.stream = False
        self.timeout = timedelta(seconds=3)
        self.query_all = False
        self.exclude_type = []
        self.output_cdn = False
        self.asn = False
        self.health_check = False
        self.disable_update_check = False
        self.pdcp_auth = ""
        self.proxy = ""

    def should_load_resume(self) -> bool:
        return self.resume and os.path.exists(DEFAULT_RESUME_FILE)

    def should_save_resume(self) -> bool:
        return True

    def configure_output(self):
        if self.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        if self.no_color:
            colorama_init(strip=True)
        if self.silent:
            logging.getLogger().setLevel(logging.ERROR)

    def configure_r_codes(self) -> Exception | None:
        self.rcodes = {}
        rcodes = [r.strip().lower() for r in self.r_code.split(",") if r.strip()]
        for rcode in rcodes:
            if rcode == "":
                continue
            if rcode == "noerror":
                rc = 0
            elif rcode == "formerr":
                rc = 1
            elif rcode == "servfail":
                rc = 2
            elif rcode == "nxdomain":
                rc = 3
            elif rcode == "notimp":
                rc = 4
            elif rcode == "refused":
                rc = 5
            elif rcode == "yxdomain":
                rc = 6
            elif rcode == "yxrrset":
                rc = 7
            elif rcode == "nxrrset":
                rc = 8
            elif rcode == "notauth":
                rc = 9
            elif rcode == "notzone":
                rc = 10
            elif rcode in ["badsig", "badvers"]:
                rc = 16
            elif rcode == "badkey":
                rc = 17
            elif rcode == "badtime":
                rc = 18
            elif rcode == "badmode":
                rc = 19
            elif rcode == "badname":
                rc = 20
            elif rcode == "badalg":
                rc = 21
            elif rcode == "badtrunc":
                rc = 22
            elif rcode == "badcookie":
                rc = 23
            else:
                try:
                    rc = int(rcode)
                except ValueError:
                    return ValueError("invalid rcode value")
            self.rcodes[rc] = True
        self.has_r_codes = bool(self.r_code)
        return None

    def configure_resume(self) -> Exception | None:
        self.resume_cfg = ResumeCfg()
        if self.resume and os.path.exists(DEFAULT_RESUME_FILE):
            with open(DEFAULT_RESUME_FILE, 'r') as f:
                data = json.load(f)
                self.resume_cfg.resume_from = data.get("ResumeFrom", "")
                self.resume_cfg.index = data.get("Index", 0)
                self.resume_cfg.current = data.get("current", "")
                self.resume_cfg.current_index = data.get("currentIndex", 0)
        return None

    def configure_query_options(self):
        query_map = {
            "a": "a",
            "aaaa": "aaaa",
            "cname": "cname",
            "ns": "ns",
            "txt": "txt",
            "srv": "srv",
            "ptr": "ptr",
            "mx": "mx",
            "soa": "soa",
            "axfr": "axfr",
            "caa": "caa",
            "any": "any",
        }
        if self.query_all:
            for key in query_map:
                setattr(self, key, True)
            self.response = True
            self.exclude_type.append("any")

        for et in self.exclude_type:
            if et in query_map:
                setattr(self, query_map[et], False)
        if not any([self.a, self.aaaa, self.cname, self.ns, self.txt, self.srv, self.ptr, self.mx, self.soa, self.axfr, self.caa, self.any]):
            self.a = True

def parse_options() -> Options:
    parser = argparse.ArgumentParser(description="dnsx is a fast and multi-purpose DNS toolkit...")
    # Input group
    input_group = parser.add_argument_group("Input")
    input_group.add_argument("-l", "--list", dest="hosts", default="", help="list of sub(domains)/hosts to resolve (file or stdin)")
    input_group.add_argument("-d", "--domain", dest="domains", default="", help="list of domain to bruteforce (file or comma separated or stdin)")
    input_group.add_argument("-w", "--wordlist", dest="word_list", default="", help="list of words to bruteforce (file or comma separated or stdin)")

    # Query group
    query_group = parser.add_argument_group("Query")
    query_group.add_argument("-a", action="store_true", help="query A record (default)")
    query_group.add_argument("-aaaa", action="store_true", help="query AAAA record")
    query_group.add_argument("-cname", action="store_true", help="query CNAME record")
    query_group.add_argument("-ns", action="store_true", help="query NS record")
    query_group.add_argument("-txt", action="store_true", help="query TXT record")
    query_group.add_argument("-srv", action="store_true", help="query SRV record")
    query_group.add_argument("-ptr", action="store_true", help="query PTR record")
    query_group.add_argument("-mx", action="store_true", help="query MX record")
    query_group.add_argument("-soa", action="store_true", help="query SOA record")
    query_group.add_argument("-any", action="store_true", help="query ANY record")
    query_group.add_argument("-axfr", action="store_true", help="query AXFR")
    query_group.add_argument("-caa", action="store_true", help="query CAA record")
    query_group.add_argument("-recon", "--all", action="store_true", dest="query_all", help="query all the dns records")
    query_group.add_argument("-e", "--exclude-type", action="append", default=[], dest="exclude_type", help="dns query type to exclude")

    # Filter group
    filter_group = parser.add_argument_group("Filter")
    filter_group.add_argument("-re", "--resp", action="store_true", dest="response", help="display dns response")
    filter_group.add_argument("-ro", "--resp-only", action="store_true", dest="response_only", help="display dns response only")
    filter_group.add_argument("-rc", "--rcode", dest="r_code", default="", help="filter result by dns status code")
    filter_group.add_argument("-rtf", "--response-type-filter", dest="response_type_filter", default="", help="return entries with no records for the specified query types")

    # Probe group
    probe_group = parser.add_argument_group("Probe")
    probe_group.add_argument("-cdn", action="store_true", dest="output_cdn", help="display cdn name")
    probe_group.add_argument("-asn", action="store_true", help="display host asn information")

    # Rate-limit group
    rate_group = parser.add_argument_group("Rate-limit")
    rate_group.add_argument("-t", "--threads", type=int, default=100, help="number of concurrent threads to use")
    rate_group.add_argument("-rl", "--rate-limit", type=int, default=-1, help="number of dns request/second to make")

    # Update group
    update_group = parser.add_argument_group("Update")
    update_group.add_argument("-up", "--update", action="store_true", help="update dnsx to latest version")
    update_group.add_argument("-duc", "--disable-update-check", action="store_true", help="disable automatic dnsx update check")

    # Output group
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("-o", "--output", dest="output_file", default="", help="file to write output")
    output_group.add_argument("-j", "--json", action="store_true", help="write output in JSONL format")
    output_group.add_argument("-or", "--omit-raw", action="store_true", help="omit raw dns response from jsonl output")

    # Debug group
    debug_group = parser.add_argument_group("Debug")
    debug_group.add_argument("-hc", "--health-check", action="store_true", help="run diagnostic check up")
    debug_group.add_argument("--silent", action="store_true", help="display only results in the output")
    debug_group.add_argument("-v", "--verbose", action="store_true", help="display verbose output")
    debug_group.add_argument("--raw", "--debug", action="store_true", help="display raw dns response")
    debug_group.add_argument("--stats", action="store_true", dest="show_statistics", help="display stats of the running scan")
    debug_group.add_argument("--version", action="store_true", help="display version of dnsx")
    debug_group.add_argument("-nc", "--no-color", action="store_true", help="disable color in output")

    # Optimization group
    optim_group = parser.add_argument_group("Optimization")
    optim_group.add_argument("--retry", type=int, default=2, help="number of dns attempts to make")
    optim_group.add_argument("-hf", "--hostsfile", action="store_true", dest="hosts_file", help="use system host file")
    optim_group.add_argument("--trace", action="store_true", help="perform dns tracing")
    optim_group.add_argument("--trace-max-recursion", type=int, default=255, help="Max recursion for dns trace")
    optim_group.add_argument("--resume", action="store_true", help="resume existing scan")
    optim_group.add_argument("--stream", action="store_true", help="stream mode")
    optim_group.add_argument("--timeout", type=int, default=3, help="maximum time to wait for a DNS query to complete")

    # Configs group
    config_group = parser.add_argument_group("Configurations")
    config_group.add_argument("--auth", dest="pdcp_auth", default="true", help="configure ProjectDiscovery Cloud Platform api key")
    config_group.add_argument("-r", "--resolver", default="", help="list of resolvers to use (file or comma separated)")
    config_group.add_argument("-wt", "--wildcard-threshold", type=int, default=5, help="wildcard filter threshold")
    config_group.add_argument("-wd", "--wildcard-domain", default="", help="domain name for wildcard filtering")
    config_group.add_argument("--proxy", default="", help="proxy to use")

    args = parser.parse_args()

    options = Options()
    # map all args to options
    options.hosts = args.hosts
    options.domains = args.domains
    options.word_list = args.word_list
    options.threads = args.threads
    options.rate_limit = args.rate_limit
    options.retries = args.retry
    options.output_file = args.output_file
    options.raw = args.raw
    options.silent = args.silent
    options.verbose = args.verbose
    options.version = args.version
    options.no_color = args.no_color
    options.response = args.response
    options.response_only = args.response_only
    options.a = args.a
    options.aaaa = args.aaaa
    options.cname = args.cname
    options.ns = args.ns
    options.txt = args.txt
    options.srv = args.srv
    options.ptr = args.ptr
    options.mx = args.mx
    options.soa = args.soa
    options.any = args.any
    options.axfr = args.axfr
    options.caa = args.caa
    options.json = args.json
    options.omit_raw = args.omit_raw
    options.trace = args.trace
    options.trace_max_recursion = args.trace_max_recursion
    options.wildcard_threshold = args.wildcard_threshold
    options.wildcard_domain = args.wildcard_domain
    options.show_statistics = args.show_statistics
    options.r_code = args.r_code
    options.response_type_filter = args.response_type_filter
    options.resume = args.resume
    options.hosts_file = args.hosts_file
    options.stream = args.stream
    options.timeout = timedelta(seconds=args.timeout)
    options.query_all = args.query_all
    options.exclude_type = args.exclude_type
    options.output_cdn = args.output_cdn
    options.asn = args.asn
    options.health_check = args.health_check
    options.disable_update_check = args.disable_update_check
    options.pdcp_auth = args.pdcp_auth
    options.proxy = args.proxy

    if options.response and options.response_only:
        logging.fatal("resp and resp-only can't be used at the same time")

    if options.retries < 1:
        logging.fatal("retries must be at least 1")

    # validate input combinations
    word_list_present = options.word_list != ""
    domains_present = options.domains != ""
    hosts_present = options.hosts != ""

    if hosts_present and (word_list_present or domains_present):
        logging.fatal("list(l) flag can not be used domain(d) or wordlist(w) flag")

    if word_list_present and not domains_present:
        logging.fatal("missing domain(d) flag required with wordlist(w) input")

    if domains_present and not word_list_present:
        logging.fatal("missing wordlist(w) flag required with domain(d) input")

    # stdin check
    if argument_has_stdin(options.domains) and argument_has_stdin(options.word_list):
        if options.stream:
            logging.fatal("argument stdin not supported in stream mode")
        logging.fatal("stdin can be set for one flag")

    if options.stream:
        if word_list_present:
            logging.fatal("wordlist not supported in stream mode")
        if domains_present:
            logging.fatal("domains not supported in stream mode")
        if options.resume:
            logging.fatal("resume not supported in stream mode")
        if options.wildcard_domain != "":
            logging.fatal("wildcard not supported in stream mode")
        if options.show_statistics:
            logging.fatal("stats not supported in stream mode")

    if options.response_type_filter != "":
        options.response_type_filter_map = [et.strip().lower() for et in options.response_type_filter.split(",") if et.strip()]

    options.configure_query_options()

    err = options.configure_r_codes()
    if err is not None:
        logging.fatal(str(err))

    err = options.configure_resume()
    if err is not None:
        logging.fatal(str(err))

    # pdcp auth
    if options.pdcp_auth == "true":
        auth_with_pdcp()
    elif len(options.pdcp_auth) == 36:
        global PDCP_API_KEY
        PDCP_API_KEY = options.pdcp_auth
        # validate and save if needed

    options.configure_output()
    show_banner()

    if options.version:
        logging.info(f"Current Version: {VERSION}")
        sys.exit(0)

    if not options.disable_update_check:
        get_update_callback()()

    return options

def argument_has_stdin(arg: str) -> bool:
    return arg == STDIN_MARKER