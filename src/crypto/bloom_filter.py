"""
Cryptographic system for bloom filter
"""
from crypto.interface import Crypto
import configparser
import glob, hashlib, os
from base64 import b64encode

# Hash and crypto import
from crypto.pybloom import BloomFilter

class Bloom_filter(Crypto):
    def __init__(self, conf, metadata=None, rate=None):
        self.conf = conf
        self.token = conf['misp']['token']
        self.passwords = list()
        self.rate = rate
        if not rate:
            self.rate = conf['bloom_filter']['error_rate']
        # If for matching
        if metadata != None:
            filename = self.conf['rules']['location'] + '/joker'
            with open(filename, 'rb') as fd:
                self.f = BloomFilter.fromfile(fd)

    def create_rule(self, ioc, message):
        """
        We need to create one rule, thus we need a state
        """
        if (len(ioc)>1):
            # We also add the concatenation of the two values
            long_pass = '||'.join([ioc[attr] for attr in ioc])
            self.passwords.append(long_pass + self.token)
        
        for attr in ioc:
            self.passwords.append(ioc[attr]+ self.token)

        return {'joker':True}


    def check(self, attributes, rule):
        """
        Return a list of password to test or an empty list
        """
        passwords = list()

        # Only exists types with two elements ( redis matching
        # has more attributes and it is not usefull to use
        # long pass )
        if (len(attributes)==2):
            # We also add the concatenation of the two values
            long_pass = '||'.join([attributes[attr] for attr in attributes])
            passwords.append(long_pass + self.token)

        for attr in attributes:
            passwords.append(attributes[attr]+ self.token)

        matchPasswords = list()
        for p in passwords:
            if p in self.f:
                matchPasswords.append(p)

        return matchPasswords
        

    def match(self, attributes, rule, queue):
        for p in self.check(attributes, rule):
            queue.put("Value(s) {} matched for {}\n".format(attributes, p[:-len(self.token)]))


    def write_bloom(self):
        # Create Bloom filter
        f = BloomFilter(capacity=len(self.passwords), error_rate=float(self.rate))
        [f.add(password) for password in self.passwords ]
        with open(self.conf['rules']['location'] + '/joker', 'wb') as fd:
            f.tofile(fd)

    def save_meta(self):
        meta = configparser.ConfigParser()
        meta['crypto'] = {}
        meta['crypto']['name'] = 'bloom_filter' 
        err_rate = self.rate
        meta['crypto']['error_rate'] = err_rate
        with open(self.conf['rules']['location'] + '/metadata', 'w') as config:
            meta.write(config)
        
        self.write_bloom()

