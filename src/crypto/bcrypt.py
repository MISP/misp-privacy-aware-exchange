"""
Cryptographic system with bcrypt
"""
from crypto.interface import Crypto
import configparser
import glob, hashlib, os
from base64 import b64encode

# hash and crypto import
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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
                desired_key_bytes = 16,
                rounds = rd)
        return key

    def create_rule(self, ioc, message):
        nonce = os.urandom(16)
        salt = os.urandom(16)

        # Spit + redo allow to ensure the same order to create the password
        attr_types = '||'.join(attr_type for attr_type in ioc)
        password = '||'.join(ioc[attr_type] for attr_type in ioc)

        # Encrypt the message
        dk = self.derive_key(password.encode('utf8'), salt, attr_types)

        backend = default_backend()
        cipher = Cipher(algorithms.AES(dk), modes.CTR(nonce), backend=backend)
        encryptor = cipher.encryptor()
        ct_check = encryptor.update(b'\x00'*16)
        ct_message = encryptor.update(message.encode('utf-8'))
        ct_message += encryptor.finalize()

        # Create the rule
        rule = {}
        rule['salt'] = b64encode(salt).decode('ascii')
        rule['attributes'] = attr_types
        rule['nonce'] = b64encode(nonce).decode('ascii')
        rule['ciphertext-check'] = b64encode(ct_check).decode('ascii')
        rule['ciphertext'] = b64encode(ct_message).decode('ascii')

        return rule

    def cryptographic_match(self, password, salt, nonce, ciphertext, attr_types):
        dk = self.derive_key(password.encode('utf8'), salt, attr_types)

        backend = default_backend()
        cipher = Cipher(algorithms.AES(dk), modes.CTR(nonce), backend=backend)
        dec = cipher.decryptor()
        # A match is found when the first block is filled with null bytes
        if dec.update(ciphertext[0]) == b'\x00'*16:
            plaintext = dec.update(ciphertext[1]) + dec.finalize()
            return (True, plaintext)
        else:
            return (False, '')


    def match(self, attributes, rule, queue):
        """
        Sometimes we don't need to decrypt the whole
        ciphertext to know if there is a match
        as it is the case here thanks to ctr mode
        """
        rule_attr = rule['attributes']
        password = ''
        try:
            password = '||'.join([attributes[attr] for attr in rule_attr])
            attr_types = '||'.join(attr_type for attr_type in rule_attr)
        except:
            pass # Nothing to do
        ciphertext = [rule['ciphertext-check'], rule['ciphertext']]
        match, plaintext = self.cryptographic_match(password, rule['salt'],\
                rule['nonce'], ciphertext, attr_types)

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

