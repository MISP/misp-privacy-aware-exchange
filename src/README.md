# src files

- crypto/         : Crypto systems packages
- benchmark/      : Benchmarking files 
- misp/           : Helpers
- benchmark.py    : Execute benchmarks
- configuration.py: Used in match\_rules and readMisp for handling configuration file 
- matchRules.py  : Check if an attribute matches a rule
- readMisp.py     : Transform misp attributes into rules (containing encrypted data)

# readMisp.py : Create rules
- help : 
	- ./readMisp.py -h
```
usage: readMisp.py [-h] [--misp MISP] [-v]

Create an encrypted IOC rule.

optional arguments:
  -h, --help     show this help message and exit
  --misp MISP    web (for web api);mysql (directly from mysql)
  -v, --verbose  Explain what is being done

```
- Read from mysql : 
	- copy configuration.orig to configuration in the conf directory (../conf)
	- fill in the misp, misp mysql, pbkdf2 and rules sections
	- ./readmisp --misp mysql 
- Read from misp web api :
	- copy configuration.orig to configuration in the conf directory (../conf)
	- fill the misp, misp web api and rules sections
	- ./readmisp --misp web
  
# matchRules.py : check for a match
- help :
	- ./matchRules.py -h
  ```
usage: matchRules.py [-h] [--input INPUT] [-v] [-p MULTIPROCESS]
                     [attribute [attribute ...]]

Evaluate a network dump against rules.

positional arguments:
  attribute             key-value attribute eg. ip=192.168.0.0 port=5012

optional arguments:
  -h, --help            show this help message and exit
  --input INPUT         input is redis, argument or rangeip (testing purpose)
  -v, --verbose         Shows progress bar
  -p MULTIPROCESS, --multiprocess MULTIPROCESS
                        Use multiprocess, the maximum is the number of cores
                        minus 1 (only for redis)

  ```
