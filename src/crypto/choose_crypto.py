def Crypto(name, conf, metadata=None):
    if (name == 'pbkdf2'):
        from crypto.pbkdf2 import Pbkdf2
        return Pbkdf2(conf, metadata)
    elif (name == 'bcrypt'):
        from crypto.bcrypt import Bcrypt
        return Bcrypt(conf, metadata)
    elif (name == 'bloom_filter'):
        from crypto.bloom_filter import Bloom_filter
        return Bloom_filter(conf, metadata)
    elif (name.startswith('bloomy_')):
        from crypto.bloomy import Bloomy
        return Bloomy(conf, metadata, name[7:])
    else:
        print('Not recognized')
