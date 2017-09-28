from recon.core.module import BaseModule

class Module(BaseModule):

    meta = {
        'name': 'OTX Pulse HTTP/S Port and SubjectAltName Enumerator',
        'author': 'j nazario (@jnazario)',
        'description': 'Leverages the OTX Pulse API to enumerate other virtual hosts sharing the same IP address. Updates the \'hosts\' and \'domains\' table with the results.',
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
                if 'certificate subject' in x['key']:
                    key = x[u'key']
                    hostname = x[u'value']
                    port = int(key.split()[0])
                    self.add_ports(port=port, host=hostname)
                    self.output('\'%s:%d\' successfully found.' % (hostname, port))
