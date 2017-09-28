from recon.core.module import BaseModule

class Module(BaseModule):

    meta = {
        'name': 'OTX Pulse SubjectAltName Enumerator',
        'author': 'j nazario (@jnazario)',
        'description': 'Leverages the OTX Pulse API to enumerate other domains sharing the same hostname. Updates the \'domains\' table with the results.',
        'query': 'SELECT DISTINCT host FROM hosts WHERE host IS NOT NULL',
    }

    def module_run(self, hosts):
        for host in hosts:
            url = 'https://otx.alienvault.com/api/v1/indicators/hostname/{0}/http_scans'.format(host)
            resp = self.request(url)
            jsonobj = resp.json
            if jsonobj.has_key('Error'):
                self.error(jsonobj['Error'])
                continue
            for x in jsonobj['data']:
                if 'certificate subject' in x['key'] and '*.' in x['value']:
                    domain = x[u'value'].replace('*.', '')
                    self.add_domains(domain)
                    self.output('\'%s\' successfully found.' % (domain, ))
