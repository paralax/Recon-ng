from recon.core.module import BaseModule

class Module(BaseModule):

    meta = {
        'name': 'OTX Pulse Certificate Subject Enumerator',
        'author': 'j nazario (@jnazario)',
        'description': 'Leverages the OTX Pulse API to discover the certificate subject for the hostame. Updates the \'companies\' table with the results.',
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
                if x[u'name'].endswith('Certificate Subject'):
                    company = x[u'value']
                    self.add_companies(company=company)
                    self.output('\'%s\' successfully found.' % (company, ))
