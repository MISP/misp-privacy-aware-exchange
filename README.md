# misp-privacy-aware-exchange
A privacy-aware exchange module to securely and privately share your indicators

# Starting point
The starting point was this article with their prove of concept implementation:
> van de Kamp, T., Peter, A., Everts, M. H., & Jonker, W. (2016, October). Private Sharing of IOCs and Sightings. In Proceedings of the 2016 ACM on Workshop on Information Sharing and Collaborative Security (pp. 35-38). ACM.

The basic idea is to transform and IOC (indicator of compromise) into something sharable but that does not leak any information.
Of course, as we want data to be retrievable from a user it is thus possible for an attacker to brute force the data. But we want it to be as difficult as possible.

The general concept is thus :

Rule(sharable IOC) creation
```python
for each misp attribute:
    create a "secret message"
    derive a key from the values of the attributes, the user token and a salt
    encrypt the secret message with this derived key
    save it as a "rule"
```

Matching
```python
for each rule:
    Try to decipher the secret message
    if it matches:
        return the value
```

Then, I've tried to make a code modular to be able to add new crypto systems on it.

# Structure
conf/ contains all configurations in the configuration file (= configuration.orig)

src/ contains all the source files

# Setup
- Install python3 and pip3
- apt-get install libmysqlclient-dev build-essential libssl-dev libffi-dev python-dev
- pip3 install -r requirements.txt

# Setup Misp Virtual Machine (testing purpose)
- Image available on : https://circl.lu/services/misp-training-materials/

if we need to access the database from an other host, add remove sql access: (on the vm)
```
- vim /etc/mysql/my.cnf
- replace line "bind-address = 127.0.0.1" by "# bind-address = 127.0.0.1"
- mysql -uroot -pPassword1234
- CREATE USER 'user'@'%' IDENTIFIED BY 'Password1234';
- GRANT ALL ON *.* TO 'user'@'%';
```


# Examples
- cd conf
- cp configuration.orig configuration
- nano configuration
- fill in misp/rules/pbkdf2 sections and save it
- cd ..
- ./readMisp.py -v
- ./matchRules.py ip-dst=192.168.1.1

# Master thesis
This project comes from the master thesis done with the help of Conostix: 
https://github.com/charly077/thesis