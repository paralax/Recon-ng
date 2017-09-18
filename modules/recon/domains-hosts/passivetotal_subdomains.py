from recon.core.module import BaseModule
from recon.utils.parsers import parse_hostname
from urlparse import urlparse
import re

class Module(BaseModule):

    meta = {
        'name': 'Passive Total Subdomains Enumerator',
        'author': 'Vlad Styran (@c2FwcmFu)',
        'description': 'Leverages the RiskIQ Passive Total API to list DNS subdomains. Updates the \'hosts\' table with the results. Requires your account API username and secret, obtain at https://www.passivetotal.org/settings.',
        'required_keys': ['passivetotal_username', 'passivetotal_secret'],
        'query': 'SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL'
    }

    def module_run(self, domains):
        for domain in domains:
            self.heading(domain, level=0)
            hosts = []
            results = []
            results = self.get_passivetotal_subdomains(domain)
            for host in results:
                if host.endswith('.'+domain) and host not in hosts:
                    hosts.append(host)
                    self.add_hosts(host)