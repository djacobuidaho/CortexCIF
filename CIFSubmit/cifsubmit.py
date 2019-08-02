#!/usr/bin/env python3
# encoding: utf-8

'''
A Cortex Analyzer that retrieves results from a local CIF server
'''

from cifsdk.client.http import HTTP as Client
from cortexutils.responder import Responder


class CIFSubmit(Responder):
    def __init__(self):
        # Bootstrap our ancestor
        Responder.__init__(self)
        # Pull the API token from the application.conf config section
        self.tokens = self.get_param('config.tokens',
                                    None,
                                    'API key is missing')
        # Pull the remote CIF URL from the application.conf config section
        self.remotes = self.get_param('config.remotes',
                                     None,
                                     'Remote CIF host is missing')
        # Pull the default tags from the application.conf config section
        self.tags = self.get_param('config.tags',
                                     None,
                                     'Tags are missing')
        # Set the confidence from the application.conf config section
        self.confidence = self.get_param('config.confidence',
                                   None,
                                   'Confidence parameter missing')
        # Set whether to verify TLS from the application.conf config section
        self.verify = self.get_param('config.verify',
                                    None,
                                    'Verify parameter missing')
        # Run through the CIF URLs and tokens and pair them into one list
        self.cif_hosts = []
        if len(self.tokens) == len(self.remotes):
            while len(self.remotes):
                remote = self.remotes.pop()
                token = self.tokens.pop()
                cif_host = {'remote': remote, 'token': token}
                self.cif_hosts.append(cif_host)
        else:
            self.error('CIF host/API key pairing is incorrect')

    def summary(self, raw):
        # raw is the json that's returned in the report

        taxonomies = []
        level = 'suspicious'
        namespace = 'CIFLookup'
        # First, a count total results
        tag_count = len(raw['CIF'])
        predicate = 'TotalCount'
        value = tag_count
        taxonomies.append(
            self.build_taxonomy(level, namespace, predicate, value))

        # Now for each provider:tags
        for result in raw['CIF']:
            tag_list = ''
            for tag in result['tags']:
                tag_list += tag + ','
            provider = result['provider']
            predicate = 'Provider:Tags'
            value = '{0} : {1}'.format(provider, tag_list)
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {'taxonomies': taxonomies}

    def submit_cif(self, indicator):
        '''
        :param indicator: one of domain, fqdn, or hash
        :return: dictionary of results
        '''

        results = []
        for cif_host in self.cif_hosts:
            cli = Client(token=cif_host['token'],
                         remote=cif_host['remote'],
                         verify_ssl=self.verify)
            data = {
                'indicator': indicator,
                'tlp': 'amber',
                'confidence': (self.confidence/10),
                'tags': self.tags
            }
            results += cli.indicators_create(data=data)

        return results

    def run(self):
        '''
        Run the analysis here
        '''
        Responder.run(self)

        if self.data_type in ['ip', 'domain', 'fqdn', 'hash', 'mail']:
            try:
                # Just get some json, hopefully the observable
                cif = self.submit_cif(self.get_data())

                # This gets put back to the summary report object
                self.report({
                    'CIF': cif,
                    'test': self.get_data()
                })

            except ValueError as e:
                self.report(e)
        else:
            self.report('Unsupported')


if __name__ == '__main__':
    CIFSubmit().run()
