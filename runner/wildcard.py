import uuid
from threading import Lock
from dnsx.dnsx import DNSData

class Runner:
    def is_wildcard(self, host: str) -> bool:
        orig = set()
        wildcards = set()

        in_data, err = self.dnsx.query_one(host)
        if err is not None or in_data is None:
            return False
        for a in in_data.dns_data.A:
            orig.add(a)

        subdomain_part = host.removesuffix("." + self.options.wildcard_domain)
        subdomain_tokens = subdomain_part.split(".")

        hosts = [self.options.wildcard_domain]

        if len(subdomain_tokens) > 0:
            for i in range(1, len(subdomain_tokens)):
                newhost = ".".join(subdomain_tokens[i:]) + "." + self.options.wildcard_domain
                hosts.append(newhost)

        for h in hosts:
            with self.wildcards_cache_mutex:
                list_ip = self.wildcards_cache.get(h, None)
            if list_ip is None:
                rand_prefix = uuid.uuid4().hex + "." + h
                in_data, err = self.dnsx.query_one(rand_prefix)
                if err is not None or in_data is None:
                    continue
                list_ip = in_data.dns_data.A
                with self.wildcards_cache_mutex:
                    self.wildcards_cache[h] = list_ip

            for a in list_ip:
                wildcards.add(a)

        for a in orig:
            if a in wildcards:
                return True

        return False