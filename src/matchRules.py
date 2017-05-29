#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This code is inspired from https://github.com/CRIPTIM/private-IOC-sharing written by Tim van de Kamp
# which is using the MIT license

# MISP import
from configuration import Configuration

# Tools import
import argparse, configparser
import os, sys, glob, subprocess
from multiprocessing import SimpleQueue, Process, cpu_count, Lock
import json, csv, re
from functools import lru_cache
from copy import deepcopy
import redis
from normalize import normalize
from collections import OrderedDict
from progressbar import ProgressBar

# Crypto import 
import hashlib
from base64 import b64decode
from crypto.choose_crypto import Crypto

###################
# Parse arguments #
###################

parser = argparse.ArgumentParser(description='Evaluate a network dump against rules.')
parser.add_argument('attribute', nargs='*', help='key-value attribute eg. ip=192.168.0.0 port=5012')
parser.add_argument('--input', default="argument",
        help='input is redis, argument or rangeip (testing purpose)')
parser.add_argument('-v', '--verbose',\
                dest='verbose', action='store_true',\
                        help='Shows progress bar')
parser.add_argument('-p', '--multiprocess', action='store',
        type=int, help='Use multiprocess, the maximum is the number of cores minus 1 (only for redis)', default=0, )
args = parser.parse_args()

metadata = {}
conf = Configuration()

####################
# Helper functions #
####################

def iterator_result(queue):
    # Iter on a queue without infinite loop
    def next():
        if queue.empty():
            return None
        else:
            return queue.get()
    # Return iterator
    return iter(next, None)

# From the csv file, read the rules and return them as a list
def rules_from_csv(filename, lock, parse=True, printErr=True):
    lock.acquire()
    path = conf['rules']['location']+'/'+filename
    rules = list()
    if not os.path.exists(path):
        if printErr:
            print("path does not exist")
        lock.release()
        return rules
    with open(path, "r") as f:
        data = csv.DictReader(f, delimiter='\t')
        # copy data
        for d in data:
            if parse:
                d['salt'] = b64decode(d['salt'])
                d['nonce'] = b64decode(d['nonce'])
                d['attributes'] = d['attributes'].split('||')
                d['ciphertext-check'] = b64decode(d['ciphertext-check'])
                d['ciphertext'] = b64decode(d['ciphertext'])
            rules.append(d)
    lock.release()
    return rules


file_attributes = {}
rules_dict = {}

def joker(lock):
    """
    Get joker file:
        joker is a special rule that always loaded
    """
    try:
        return rules_dict[filename]
    except:
        return rules_from_csv('joker.tsv', lock, False, False)

def get_file_rules(filename, lock):
    # Get rules :
    try:
        return rules_dict[filename]
    except:
        rules_dict[filename] = rules_from_csv(filename, lock)
        return rules_dict[filename]

def get_rules(attributes, lock):
    # Get joker
    rules = joker(lock)
    # Which combinaison
    for filename in file_attributes:
        if all([i in attributes for i in file_attributes[filename]]):
            for rule in get_file_rules(filename, lock):
                rules.append(rule)
    return rules


#####################
# Process functions #
#####################
def redis_matching_process(r, queue, lock, crypto):
    # Get data
    log = r.rpop("logstash")
    while log:
        log = log.decode("utf8")
        log_dico = json.loads(log)
        ordered_dico = OrderedDico(log_dico)
        matching(ordered_dico, queue, lock, crypto)
        log = r.rpop("logstash")

def print_queue_process(queue):
    # This is an infinite loop as get waits when empty
    for elem in iter(queue.get, None):
       print(elem)


###################
# Match functions #
###################
#@lru_cache(maxsize=None)
def matching(attributes, queue, lock, crypto):
    # normalize data 
    attributes = normalize(attributes)
    # test each rules
    if args.verbose:
        bar = ProgressBar()
        for rule in bar(get_rules(attributes, lock)):
            crypto.match(attributes, rule, queue) 
    else:
        for rule in get_rules(attributes, lock):
            crypto.match(attributes, rule, queue)

def argument_matching(crypto, values=args.attribute):
    attributes = OrderedDict(pair.split("=") for pair in values)
    match = SimpleQueue()
    matching(attributes, match, Lock(), crypto)

    # Print matches (Easy to modify)
    for match in iterator_result(match):
        print(match)

def redis_matching(crypto):
    # Data is enriched in logstash
    conf = Configuration()
    r = redis.StrictRedis(host=conf['redis']['host'], port=conf['redis']['port'], db=conf['redis']['db'])

    lock = Lock()
    match = SimpleQueue()
    if args.multiprocess > 0:
        n = min(args.multiprocess, cpu_count()-1)
        processes = list()
        for i in range(n):
            process = Process(target=redis_matching_process, args=(r, match, lock, crypto))
            process.start()
            processes.append(process)

        # Print match(es)
        print_process = Process(target=print_queue_process, args=([match]))
        print_process.start()
        for process in processes:
            process.join()
        print_process.terminate()
    else:
        redis_matching_process(r, match, lock)
        for item in iterator_result(match):
            print(item)

# For Benchmarking
def rangeip_test(crypto):
    for ip4_0 in range(10):
        for ip4_1 in range(256):
            ip=['ip-dst=192.168.' + str(ip4_0) + '.' + str(ip4_1)]
            argument_matching(crypto, ip)

########
# Main #
########
if __name__ == "__main__":
    conf = Configuration()
    rules = list()
    # Get configuration
    metaParser = configparser.ConfigParser()
    metaParser.read(conf['rules']['location'] + "/metadata")
    metadata = metaParser._sections

    # Choose crypto
    crypto = Crypto(metadata['crypto']['name'], conf, metadata)

    if not os.path.exists(conf['rules']['location']):
        sys.exit("No rules found.")


    # Get all files attributes
    filenames = os.listdir(conf['rules']['location'])
    for name in filenames:
        split = (name.split('.')[0]).split('_')
        file_attributes[name] = split
    
    if args.input == "redis":
        redis_matching(crypto)
    elif args.input == "rangeip":
        rangeip_test(crypto)
    else:
        argument_matching(crypto)
