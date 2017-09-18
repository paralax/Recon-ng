from recon.core.module import BaseModule
import time
import urllib

class Module(BaseModule):

    meta = {
        'name': 'Have I been pwned? Password Search',
        'author': 'Grid (based off hibp_breach by Tim Tomes (@LaNMaSteR53) & Tyler Halfpop (@tylerhalfpop))',
        'description': 'Leverages the haveibeenpwned.com API to determine if the supplied password, or list of passwords, is in the haveibeenpnwed.com password list. Adds compromised passwords to the \'credentials\' table.',
        'comments': (
            'The API is rate limited to 1 request per 1.5 seconds.',
        ),
        'query': 'SELECT DISTINCT password FROM credentials WHERE password IS NOT NULL',
    }

    def module_run(self, passwords):
        # retrieve status
        base_url = 'https://haveibeenpwned.com/api/v2/%s/%s'
        endpoint = 'pwnedpassword'
        for password in passwords:
            resp = self.request(base_url % (endpoint, urllib.quote(password)))
            rcode = resp.status_code
            if rcode == 200:
		self.alert('%s => Password found!' % (password))
                self.add_credentials('', password)		
	    if rcode == 404:
                self.verbose('%s => Not Found.' % (password))
            elif rcode == 400:
                self.error('%s => Bad Request.' % (password))
                continue
            time.sleep(1.6)