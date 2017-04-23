"""
Create an abstract class for the cryptographic functions
Configuration must me in the configuration file
"""

class Crypto():
    def __init__(self, conf, metadata=None, cryptoName=''):
        """
        Metadata is used for matching
        """
        pass

    def create_rule(self, ioc, message):
        """
        Use the generated key and salt to 
        encrypt the message
        """
        pass

    def match(self, attributes, rule, queue):
        """
        attributes is the values to check
        rule is the rule agains which it has to be check.
            for an example it can be a bloom filter
        queue is to send the output (easier to redirect only
            one output is further needed)
        """
        pass

    def save_meta(self):
        """
        Save metadata for the specific crypto system
        """
        pass
