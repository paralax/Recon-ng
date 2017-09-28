from recon.core.module import BaseModule

class Module(BaseModule):

    meta = {
        'name': 'OTX Pulse SubjectAltName Enumerator',
        'author': 'j nazario (@jnazario)',
        'description': 'Leverages the OTX Pulse API to enumerate other virtual hosts sharing the same hostname. Updates the \'hosts\' table with the results.',
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
                if ('certificate subject' in x['key'] and '*.' not in x['value']) or 'a_domains' in x['key']:
                    hostname = x[u'value']
                    self.add_host(host=hostname)
                    self.output('\'%s\' successfully found.' % (hostname, ))
