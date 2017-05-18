"""
Create an abstract class for the cryptographic functions
"""
from crypto.interface import Crypto
from crypto.helper import *
import configparser
import glob, os, hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class SHA(Crypto):
    def __init__(self, conf, name, metadata=None):
        print(name)
        # check the name and raise error otherwise
        if name not in ['sha256', 'sha384', 'sha512']:
            raise BaseException('Algorithm is not accepted, try in sha256, sha385, sha521')
        self.conf = conf
        self.hash_name = name
        self.btoken = bytes(conf['misp']['token'], encoding='ascii')
        # For matching (only token is kept from config file)
        if metadata is not None:
            metadata = metadata['crypto']
            self.hash_name = name

    def derive_key(self, bpassword, bsalt, attr_types):
        """
        Generate the key for encryption
        """
        name = self.hash_name
        if name == 'sha256':
            theHash = hashes.SHA256()
        elif name == 'sha384':
            theHash = hashes.SHA284()
        elif name == 'sha512':
            theHash = hashes.SHA512()

        digest = hashes.Hash(theHash, backend=default_backend())
        digest.update(bpassword + self.btoken + bsalt)
        return digest.finalize() 

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
        meta['crypto']['name'] = self.hash_name
        with open(self.conf['rules']['location'] + '/metadata', 'w') as config:
            meta.write(config)

