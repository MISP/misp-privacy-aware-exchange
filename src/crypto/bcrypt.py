"""
Cryptographic system with bcrypt
"""
from crypto.interface import Crypto
from crypto.helper import *
import configparser
import glob, hashlib, os
from base64 import b64encode

# hash and crypto import
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import bcrypt

class Bcrypt(Crypto):
    def __init__(self, conf, metadata=None):
        self.conf = conf
        self.btoken = bytes(conf['misp']['token'], encoding='ascii')
        self.round = int(self.conf['bcrypt']['round'])
        self.ipround = int(self.conf['bcrypt']['ipround'])
        # For matching (only token is kept from config file)
        if metadata is not None:
            metadata = metadata['crypto']
            self.round = int(metadata['round'])
            self.ipround = int(metadata['ipround'])

    def derive_key(self, bpassword, bsalt, attr_types):
        """
        Generate the key used for encryption
        Bcrypt truncates password to 72 bytes. 
            password + token : For long data, token will not be included
            token + password : only use 32 bytes of data
            => Hash (password + token) as the password
        """
        rd = 1
        if attr_types in ["ip-dst", "ip-src", "ip-src||port", "ip-dst||port"]:
            rd = self.ipround
        else:
            rd = self.round
        # Solve the truncation problem
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bpassword)
        digest.update(self.btoken)
        token_pass = digest.finalize()
        key =  bcrypt.kdf(password = token_pass, 
                salt = bsalt,
                desired_key_bytes = 32,
                rounds = rd)
        return key

    def create_rule(self, ioc, message):
        salt = os.urandom(16)
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
        except:
            pass # Nothing to do
        dk = self.derive_key(password.encode('utf8'), rule['salt'], attr_types)
        ciphertext = [rule['ciphertext-check'], rule['ciphertext']]
        match, plaintext = aes_match_rule(dk, password, rule['nonce'],\
                ciphertext)

        if match:
            queue.put("IOC matched for: {}\nSecret Message (uuid-event id-date)\n===================================\n{}\n".format(attributes, plaintext.decode('utf-8')))



    def save_meta(self):
        meta = configparser.ConfigParser()
        meta['crypto'] = {}
        meta['crypto']['name'] = 'bcrypt' 
        meta['crypto']['round'] = str(self.round)
        meta['crypto']['ipround'] = str(self.ipround)
        with open(self.conf['rules']['location'] + '/metadata', 'w') as config:
            meta.write(config)

