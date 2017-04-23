"""
Create an abstract class for the cryptographic functions
"""
from crypto.interface import Crypto
import configparser
import glob, hashlib, os
from base64 import b64encode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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
        if attr_types in ["ip-dst", "ip-src", "ip-src||port", "ip-dst||port"]:
            it = self.ipiterations
        else:
            it = self.iterations
        return hashlib.pbkdf2_hmac(self.hash_name, bpassword + self.btoken, bsalt, it, dklen=self.dklen)

    def create_rule(self, ioc, message):
        nonce = os.urandom(16)
        salt = os.urandom(hashlib.new(self.hash_name).digest_size)

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
        # A match is found when the first block is all null bytes
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
            pass # nothing to do
        ciphertext = [rule['ciphertext-check'], rule['ciphertext']]
        match, plaintext = self.cryptographic_match(password, rule['salt'],\
                rule['nonce'], ciphertext, attr_types)

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

