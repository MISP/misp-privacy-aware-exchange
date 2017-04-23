"""
The goal of this implementation is to mix a bloom filter
with false positive rate of 50% in order to :
    -> make matching system faster
    -> Do not give too many information only with the bloomFilter
with a standard choosen key derivation function
"""
from crypto.interface import Crypto
from crypto.bloom_filter import Bloom_filter as BF
from crypto.choose_crypto import Crypto as ChooseCrypto
from configparser import ConfigParser

class Bloomy(Crypto):
    def __init__(self, conf, metadata=None, cryptoName=''):
        self.conf = conf
        self.Crypto = ChooseCrypto(cryptoName, conf, metadata)
        # Set up bloom
        self.bloom = BF(conf, metadata=metadata, rate=0.5)

    def create_rule(self, ioc, message):
        self.bloom.create_rule(ioc, message)
        return self.Crypto.create_rule(ioc, message)

    def match(self, attributes, rule, queue):
        if len(self.bloom.check(attributes, rule))>0:
            self.Crypto.match(attributes, rule, queue)

    def save_meta(self):
        conf = self.conf
        # Create bloom filter
        self.bloom.write_bloom()
        # Save metadat
        self.Crypto.save_meta()
        # Add bloomy_
        metaParser = ConfigParser()
        metaParser.read(conf['rules']['location'] + '/metadata')
        metadata = metaParser._sections
        cryptoName = 'bloomy_' + metadata['crypto']['name']
        metaParser['crypto']['name'] = cryptoName
        with open(conf['rules']['location'] + '/metadata', 'w') as config:
            metaParser.write(config)

