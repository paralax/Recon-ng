from recon.core.module import BaseModule
from datetime import datetime
import re
import socket

from BeautifulSoup import BeautifulSoup

# for https://bitbucket.org/LaNMaSteR53/recon-ng/

class Module(BaseModule):
    meta = {
        'name': 'Robtex Passive DNS Lookups',
        'author': 'Jose Nazario',
        'description': 'Uses passive DNS data presented by Robtex to update the \'hosts\' table.',
        'comments': (
            '',
        ),
        'query': 'SELECT DISTINCT ip_address FROM hosts WHERE ip_address IS NOT NULL',
        'options': (
            ('restrict', True, True, 'restrict added hosts to current domains'),
        ),
    }
    
    def module_run(self, hosts):
        # stolen from Recon-ng / modules / recon / hosts-hosts / ssltools.py
        domains = [x[0] for x in self.query('SELECT DISTINCT domain from domains WHERE domain IS NOT NULL')]
        regex = '(?:%s)' % ('|'.join(['\.'+re.escape(x)+'$' for x in domains]))
        for ip_address in hosts:
            try:
                socket.inet_aton(ip_address)
            except socket.error:
                hosts.extend(socket.gethostbyname_ex(ip_address)[-1])
                continue
            url = 'https://www.robtex.com/en/advisory/ip/' + ip_address.replace('.', '/') + '/'
            html = self.request(url).text
            # alternatively hosts = re.findall('<li><i>([^<]+)</i></li>', html)
            soup = BeautifulSoup(html)
            span = filter(lambda x: x.attrs == [(u'id', u'shared_ma')], soup('span'))[0]
            hosts = [ x.text for x in span.findNext().findAll('i')  ]
            for host in hosts:
                # apply restriction
                if self.options['restrict'] and not re.search(regex, host):
                    continue
                self.alert('Discovered hostname: \'%s\'' % host)
                self.add_hosts(host)
