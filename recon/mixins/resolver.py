import dns

class ResolverMixin(object):

    def get_resolver(self):
        '''Returns a dnspython default resolver object configured with the framework's global options.'''
        resolver = dns.resolver.get_default_resolver()
        resolver.nameservers = [self._global_options['nameserver']]
        resolver.lifetime = 3
        resolver.domain = dns.name.Name(("",))
        return resolver
