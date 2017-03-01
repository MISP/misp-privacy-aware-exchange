#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Impact of the number of ip on time
(Time to brute force a range /24 using nIterations for ip)
"""
from helpers import DatabaseHelper as dh, randIPv4
import timeit, shlex, subprocess

nIP = 1000
nIterations = 100

def create_rules():
    command = "./readMisp.py --misp mysql --iteration 10 --ipiteration " + str(nIterations)
    args = shlex.split(command)
    subprocess.call(args)

def bruteforceIP():
    command = "./match_rules.py --input rangeip"
    args = shlex.split(command)
    subprocess.call(args)

def test_ip(name='ip_range_bruteforce'):
    db = dh()
    db.saveAttr()
    results = []
    results.append("time(s),number of ips,pbkdf2 iterations")
    for i in range(100):
        create_rules()
        time = timeit.timeit("bruteforceIP()","from __main__ import bruteforceIP", number = 2)
        result = str(time) + "," + str( i * nIP ) + "," + str(nIterations)
        print(result)
        results.append(result)
        db.addNRandomIP(nIP)

    db.restoreAttr()
    db.closedb()
    with open(name + '.csv', 'w') as f:
            f.write('\n'.join(results))

test_ip()
