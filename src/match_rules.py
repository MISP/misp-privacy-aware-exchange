#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# this code is inspired from https://github.com/CRIPTIM/private-IOC-sharing
# which is using the MIT license

# misp import
from configuration import Configuration

# tools import
import argparse, configparser
import os, sys, glob, subprocess
from multiprocessing import SimpleQueue, Process, cpu_count, Lock
import json, csv, re
from functools import lru_cache
from copy import deepcopy
import redis
from url_normalize import url_normalize
from collections import OrderedDict

# crypto import 
import hashlib
from base64 import b64decode
from crypto.choose_crypto import Crypto

parser = argparse.ArgumentParser(description='Evaluate a network dump against rules.')
parser.add_argument('attribute', nargs='*', help='key-value attribute eg. ip=192.168.0.0 port=5012')
parser.add_argument('--input', default="argument",
        help='input is redis, argument or rangeip (testing purpose)')

parser.add_argument('-p', '--multiprocess', action='store',
        type=int, help='Use multiprocess, the maximum is the number of cores minus 1 (only for redis)', default=0, )
args = parser.parse_args()

metadata = {}
conf = Configuration()

####################
# helper functions #
####################

def iter_queue(queue):
    # iter on a queue without infinite loop
    def next():
        if queue.empty():
            return None
        else:
            return queue.get()
    # return iterator
    return iter(next, None)

# from the csv file, read the rules and return them as a list
def rules_from_csv(filename, lock, parse=True):
    lock.acquire()
    path = conf['rules']['location']+'/'+filename
    rules = list()
    if not os.path.exists(path):
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
        joker is a special rule that always need to be laoded
    """
    try:
        return rules_dict[filename]
    except:
        try:
            rules_dict['joker'] = rules_from_csv('joker.tsv', lock, False)
        except:
            rules_dict['joker'] = list()
        return rules_dict['joker']

def get_file_rules(filename, lock):
    # get rules :
    try:
        return rules_dict[filename]
    except:
        rules_dict[filename] = rules_from_csv(filename, lock)
        return rules_dict[filename]

def get_rules(attributes, lock):
    # get joker
    rules = joker(lock)
    # wich combinaison
    for filename in file_attributes:
        if all([i in attributes for i in file_attributes[filename]]):
            for rule in get_file_rules(filename, lock):
                rules.append(rule)
    return rules

# small normalization to increase matching
def normalize(ioc):
    for attr_type in ioc:
        # distinction bewtwee url|uri|link is often misused
        # Thus they are considered the same
        if attr_type == 'url' or\
            attr_type == 'uri' or\
            attr_type == 'link':
                ioc[attr_type] = url_normalize(ioc[attr_type])
        elif attr_type == 'hostname':
            ioc[attr_type] = ioc[attr_type].lower() 
    return ioc


#####################
# process functions #
#####################
def redis_matching_process(r, queue, lock, crypto):
    # get data
    log = r.rpop("logstash")
    while log:
        log = log.decode("utf8")
        log_dico = json.loads(log)
        ordered_dico = OrderedDico(log_dico)
        dico_matching(ordered_dico, queue, lock, crypto)
        log = r.rpop("logstash")

def print_queue_process(queue):
    # this is an infinite loop as get waits when empty
    for elem in iter(queue.get, None):
       print(elem)


###################
# match functions #
###################
#@lru_cache(maxsize=None)
def dico_matching(attributes, queue, lock, crypto):
    # normalize data 
    attributes = normalize(attributes)
    # test each rules
    for rule in get_rules(attributes, lock):
        crypto.match(attributes, rule, queue)

def argument_matching(crypto, values=args.attribute):
    attributes = OrderedDict(pair.split("=") for pair in values)
    match = SimpleQueue()
    dico_matching(attributes, match, Lock(), crypto)

    # print matches
    for match in iter_queue(match):
        print(match)

def redis_matching(crypto):
    # data is enriched in logstash
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

        # print match if there are some
        print_process = Process(target=print_queue_process, args=([match]))
        print_process.start()
        for process in processes:
            process.join()
        print_process.terminate()
    else:
        redis_matching_process(r, match, lock)
        for item in iter_queue(match):
            print(item)

# for Benchmarking
def rangeip_matching(crypto):
    for ip4 in range(256):
        ip=["ip-dst=192.168.0." + str(ip4)]
        argument_matching(crypto, ip)

########
# Main #
########
if __name__ == "__main__":
    conf = Configuration()
    rules = list()
    # get configuration
    metaParser = configparser.ConfigParser()
    metaParser.read(conf['rules']['location'] + "/metadata")
    metadata = metaParser._sections

    # choose crypto
    crypto = Crypto(metadata['crypto']['name'], conf, metadata)

    if not os.path.exists(conf['rules']['location']):
        sys.exit("No rules found.")


    # get all files attribbutes
    filenames = os.listdir(conf['rules']['location'])
    for name in filenames:
        split = (name.split('.')[0]).split('_')
        file_attributes[name] = split

    if args.input == "redis":
        redis_matching(crypto)
    elif args.input == "rangeip":
        rangeip_matching(crypto)
    else:
        argument_matching(crypto)
