"""
Create an abstract class for the cryptographic functions
"""
from crypto.interface import Crypto
from crypto.helper import *
import configparser
import glob, hashlib, os

class Pbkdf2(Crypto):
    def __init__(self, conf, metadata=None):
        self.conf = conf
        self.hash_name = conf['pbkdf2']['hash_name']
        self.dklen = int(conf['pbkdf2']['dklen'])
        self.btoken = bytes(conf['misp']['token'], encoding='ascii')
        self.iterations = int(self.conf['pbkdf2']['iterations'])
        self.ipiterations = int(self.conf['pbkdf2']['ipiterations'])
        # For matching (only token is kept from config file)
        if metadata is not None:
            metadata = metadata['crypto']
            self.hash_name = metadata['hash_name']
            self.dklen = int(metadata['dklen'])
            self.iterations = int(metadata['iterations'])
            self.ipiterations = int(metadata['ipiterations'])

    def derive_key(self, bpassword, bsalt, attr_types):
        """
        Generate the key for encryption
        """
        it = 1
        if 'ip' in attr_types:
            it = self.ipiterations
        else:
            it = self.iterations
        return hashlib.pbkdf2_hmac(self.hash_name, bpassword + self.btoken, bsalt, it, dklen=self.dklen)

    def create_rule(self, ioc, message):
        salt = os.urandom(hashlib.new(self.hash_name).digest_size)
        attr_types, password = get_types_values(ioc)
        dk = self.derive_key(password.encode('utf8'), salt, attr_types)
        return aes_create_rule(dk, message, attr_types, salt)

    def match(self, attributes, rule, queue):
        """
        Sometimes we don't need to decrypt the whole
        ciphertext to know if there is a match
        as it is the case here thanks to ctr mode
        """
        rule_attr = rule['attributes']
        match = False
        try:
            password = '||'.join([attributes[attr] for attr in rule_attr])
            attr_types = '||'.join(attr_type for attr_type in rule_attr)
            ciphertext = [rule['ciphertext-check'], rule['ciphertext']]
            dk = self.derive_key(password.encode('utf8'), rule['salt'], attr_types)
            match, plaintext = aes_match_rule(dk, password,\
                    rule['nonce'], ciphertext)
        except:
            pass # nothing to do

        if match:
            queue.put("IOC matched for: {}\nSecret Message (uuid-event id-date)\n===================================\n{}\n".format(attributes, plaintext.decode('utf-8')))



    def save_meta(self):
        meta = configparser.ConfigParser()
        meta['crypto'] = {}
        meta['crypto']['name'] = 'pbkdf2' 
        meta['crypto']['hash_name'] = self.conf['pbkdf2']['hash_name']
        meta['crypto']['dklen'] = self.conf['pbkdf2']['dklen'] # AES block size
        meta['crypto']['iterations'] = str(self.iterations)
        meta['crypto']['ipiterations'] = str(self.ipiterations)
        with open(self.conf['rules']['location'] + '/metadata', 'w') as config:
            meta.write(config)

