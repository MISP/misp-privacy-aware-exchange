# Crypto System package
Cryptographic functions used for matching or creating rules are implemented as modules.


# Improve the matching performance with bloom filters
In order to improve the performance of the key derivation function,
the idea was to add a bloom filter with a 0.5 false positive rate.

For that, only need to add 'bloomy\_' before the name of the crypto module to use in the configuration file.

ex: [rules][cryptomodule] pbkdf2 => bloomy\_pbkdf2

# List

- pbkdf2
- bcrypt
- bloom\_filter


# Add a crypto system
- Create a new python3 class that implements Crypto from interface.py
- Modify choose\_crypto.py to import the right functions
