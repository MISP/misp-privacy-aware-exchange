import os
from base64 import b64encode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


#######
# IOC #
#######
def get_types(ioc):
    return '||'.join(attr_type for attr_type in ioc)

def get_values(ioc):
    return '||'.join(ioc[attr_type] for attr_type in ioc)

def get_types_values(ioc):
    return (get_types(ioc), get_values(ioc))


#######
# AES #
#######
def aes_create_rule(key, message, attr_types, salt):
    if len(key) < 32:
        print('Key length is not enough, It is adviced to change the algorithm used!')
    nonce = os.urandom(16)

    # Encrypt
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=backend)
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

def aes_match_rule(key, password, nonce, ciphertext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=backend)
    dec = cipher.decryptor()
    # A match is found when the first block is all null bytes
    if dec.update(ciphertext[0]) == b'\x00'*16:
        plaintext = dec.update(ciphertext[1]) + dec.finalize()
        return (True, plaintext)
    else:
        return (False, '')

