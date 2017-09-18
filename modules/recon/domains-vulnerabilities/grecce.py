from recon.core.module import BaseModule
from recon.mixins.search import GoogleWebMixin
from itertools import groupby
import json
import os
import urlparse

def _optionize(s):
    return 'ghdb_%s' % (s.replace(' ', '_').lower())

def _build_options(ghdb):
    categories = []
    for key, group in groupby([x['category'] for x in sorted(ghdb, key=lambda x: x['category'])]):
        categories.append((_optionize(key), False, True, 'enable/disable the %d sites in this category' % (len(list(group)))))
    return categories

class Module(BaseModule, GoogleWebMixin):

    with open(os.path.join(BaseModule.data_path, 'ghdb.json')) as fp:
        ghdb = json.load(fp)

    meta = {
        'name': 'Google Reconnaissance (ghdb)',
        'author': 'John Q. Public (jnqpblc)',
        'description': 'Searches for possible support forum posts, web technologies by extention, and uses BishopFox\'s GHDB list to query for results associated with a specific domain by leveraging the \'domain\' and the \'site\' search operator. Updates the \'vulnerabilities\' table with the results.',
        'comments': (
            '',
        ),
        'query': 'SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL',
        'options': [
            ('sites', 'data/grecce_sites.txt', False, 'file containing an alternate list of Google sites'),
            ('extentions', 'data/grecce_extentions.txt', False, 'file containing a list of extentions'),
            ('bishopfox', 'data/grecce_bishopfox.txt', False, 'file containing the combinded GHDB list from BishopFox'),
        ],
    }

    def module_run(self, domains):
        sites = self.ghdb
        # use list of sites if the option is set
        if self.options['sites'] and os.path.exists(self.options['sites']):
            with open(self.options['sites']) as fp:
                sites = [x.strip() for x in fp.readlines()]
        	for domain in domains:
        	    self.heading(domain, level=0)
        	    base_query = '\"*@%s\"' % (domain)
        	    for site in sites:
        	        # build query based on sites list
        	        if isinstance(site, basestring):
        	            site_query = 'site:%s' % (site)
        	            query = ' '.join((base_query, site_query))
        	            self._search(query)

        extentions = self.ghdb
        # use list of extentions if the option is set
        if self.options['extentions'] and os.path.exists(self.options['extentions']):
            with open(self.options['extentions']) as fp:
                extentions = [x.strip() for x in fp.readlines()]
	        for domain in domains:
	            self.heading(domain, level=0)
	            base_query = 'site:%s' % (domain)
	            for extention in extentions:
	                # build query based on extentions list
	                if isinstance(extention, basestring):
	                    ext_query = 'ext:%s' % (extention)
	                    query = ' '.join((base_query, ext_query))
	                    self._search(query)

        bishopfox = self.ghdb
        # use BishopFox's ghdb list if the option is set
        if self.options['bishopfox'] and os.path.exists(self.options['bishopfox']):
            with open(self.options['bishopfox']) as fp:
                bishopfox = [x.strip().split(';')[4] for x in fp.readlines()]
                for domain in domains:
                    self.heading(domain, level=0)
                    base_query = 'site:%s' % (domain)
                    for entry in bishopfox:
                        # build query based on the bishopfox list
                        if isinstance(entry, basestring):
                            bf_query = '%s' % (entry)
                            query = ' '.join((base_query, bf_query))
                            self._search(query)

    def _search(self, query):
        for result in self.search_google_web(query):
            host = urlparse.urlparse(result).netloc
            data = {
                'host': host,
                'reference': query,
                'example': result,
                'category': 'Google site',
            }
            for key in sorted(data.keys()):
                self.output('%s: %s' % (key.title(), data[key]))
            print(self.ruler*50)
            self.add_vulnerabilities(**data)