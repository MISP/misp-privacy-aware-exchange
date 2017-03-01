#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Impact of the number of pbkdf2 iterations
In a db with nIP IPv4
On 192.168.0.0/24 bruteforce
"""
from helpers import DatabaseHelper as dh, randIPv4
import timeit, shlex, subprocess

nIP = 100
n_iterations = 0
iterations_step = 100

def create_rules():
    command = "./readMisp.py --misp mysql --iteration 10 --ipiteration " + str(n_iterations)
    args = shlex.split(command)
    subprocess.call(args)

def bruteforceIP():
    command = "./match_rules.py --input rangeip"
    args = shlex.split(command)
    subprocess.call(args)

def test_ip(name='ip_iterations_bruteforce'):
    global n_iterations
    db = dh()
    db.saveAttr()
    db.addNRandomIP(nIP)
    results = []
    results.append("time(s),number of ips,pbkdf2 iterations")
    for i in range(10):
        create_rules()
        time = timeit.timeit("bruteforceIP()","from __main__ import bruteforceIP", number = 2)
        result = str(time) + "," + str( nIP ) + "," + str(n_iterations)
        print(result)
        results.append(result)
        n_iterations = n_iterations + iterations_step

    db.restoreAttr()
    db.closedb()
    with open(name + '.csv', 'w') as f:
            f.write('\n'.join(results))

test_ip()
