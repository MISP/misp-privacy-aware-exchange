# src files

- crypto/         : Crypto systems packages
- benchmark/      : Benchmarking files 
- misp/           : Helpers
- configuration.py: Used in match\_rules and readMisp for handling configuration file 
- matchRules.py  : Check if an attribute matches a rule
- readMisp.py     : Transform misp attributes into rules (containing encrypted data)
- addIOC.py      : Add new rules from new IOCs (from csv, console or automatic res update)

# readMisp.py : Create rules
- help : 
  - ./readMisp.py -h
```
usage: readMisp.py [-h] [--misp MISP] [--csvname CSVNAME] [-v]

Create an encrypted IOC rule.

optional arguments:
  -h, --help         show this help message and exit
  --misp MISP        web (for web api);mysql (directly from mysql); res for
                     the csv
  --csvname CSVNAME  Name of the csv in the res/ folder
  -v, --verbose      Explain what is being done

```
- Read from mysql : 
  - copy configuration.orig to configuration in the conf directory (../conf)
  - fill in the misp, misp mysql, pbkdf2 and rules sections
  - ./readmisp --misp mysql 
- Read from misp web api :
  - copy configuration.orig to configuration in the conf directory (../conf)
  - fill the misp, misp web api and rules sections
  - ./readmisp --misp web

# addIOC.py :
Finally, instead of regenerating all rules, this script allows to add new rules either one by one directly on the terminal, or by using a csv or also, if using readMisp with '--misp web' then, it can be used to automatically get new IOCs in a csv format and then creating the rules.
- help : 
  - ./addIOC.py -h
```
usage: addIOC.py [-h] [--misp MISP] [--CSVname CSVNAME] [-v] [-u]

Add new rules to already generated ones.

optional arguments:
  -h, --help         show this help message and exit
  --misp MISP        form for filling the form OR res to get data from res in
                     a CSV file
  --CSVname CSVNAME  Name of the CSV in the res/ folder (Without .csv)
  -v, --verbose      Explain what is being done
  -u, --updateRes    Download new IOCs from misp web api and then, compare
                     with old res to create the new rules
```
 
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
