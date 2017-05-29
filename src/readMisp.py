#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# this code is inspired from https://github.com/CRIPTIM/private-IOC-sharing
# which is using the MIT license

# misp import
from configuration import Configuration
from misp import web_api
from normalize import normalize
import requests, csv, json


# tools import
import argparse, configparser
import sys, subprocess, os, shutil
import datetime, copy, re
from url_normalize import url_normalize
from collections import OrderedDict
from progressbar import ProgressBar

# crypto import
import glob, hashlib, os
from base64 import b64encode
from crypto.choose_crypto import Crypto

# mysql import
from sqlalchemy.ext.automap import automap_base
from sqlalchemy import create_engine
from sqlalchemy.schema import MetaData, Table
from sqlalchemy.sql import select

args = {}

####################
# Global Variables #
####################
conf = Configuration()
token = bytes(conf['misp']['token'], encoding='ascii')

# IOC list 
IOCs = list()

##########
# Helper #
##########
# Used for verbose
def printv(value):
    if args.verbose:
        print(value)

def ioc_web():
    printv("Get data from misp")
    web_api.get_IOCs()
    ioc_csv()

def ioc_csv():
    printv("Cache misp data")
    with open("../res/"+ args.csvname +".csv", "r") as f:
        data = csv.DictReader(f)
        for d in data:
            IOCs.append(d)

def ioc_mysql():
    printv("Connection to mysql database")
    Base = automap_base()
    engine = create_engine('mysql://{}:{}@{}/{}'.format(conf['mysql']['user'], conf['mysql']['password'], conf['mysql']['host'], conf['mysql']['dbname']))

    Base.prepare(engine, reflect=True)
    metadata = MetaData()
    metadata.reflect(bind=engine)
    connection = engine.connect()
    attributes_table = Table("attributes", metadata, autoload=True)
    users_table = Table("users", metadata, autoload=True)

    # MISP token must be the same as the authkey
    printv("Check authentication key (token)")
    query = select([users_table.c.authkey]).where(users_table.c.email == conf['misp']['email'])
    resp = connection.execute(query)
    for authkey in resp:
        if not conf['misp']['token'] == authkey[0]:
            sys.exit("Your misp_token must be your authentication key. Please check your configuration file")

    # Get all ids attributes 
    printv("Get Attributes")
    attributes = connection.execute(select([attributes_table]))
    for attr in attributes:
        dic_attr = OrderedDict(attr.items())
        if dic_attr['to_ids'] == 1:
            timestamp = dic_attr['timestamp']
            dic_attr['date'] = datetime.datetime.fromtimestamp(int(timestamp)).strftime("%Y%m%d")
            dic_attr['value'] = dic_attr['value1']
            if (attr['value2']):
                dic_attr['value'] = dic_attr['value'] + '|' + dic_attr['value2']
            IOCs.append(dic_attr)

def create_message(attr):
    # conf rules: message = uuid event_id date
    #conf = Configuration()
    message_attr = (conf['rules']['message']).split(" ")
    message = ""
    for mattr in message_attr:
        message += ',' + str(attr[mattr])
    return message[1:]

def parse_attribute(attr, crypto, bar, i):
    bar.update(i)
    # IOC can be composed of a unique attribute type or of a list of attribute types
    split_type = attr["type"].split('|')
    ioc = OrderedDict()
    if (len(split_type)>1):
        # more than one value
        split_value = attr["value"].split('|')
        for i in range(len(split_type)):
            ioc[split_type[i]] = split_value[i]
    else:
        ioc[attr["type"]] = attr["value"]
    ioc = normalize(ioc)
    msg = create_message(attr)
    return crypto.create_rule(ioc, msg)

def parsing(IOCs, crypto, iocDic={}):
	# Parse IOCs
    printv("Create rules")
    with ProgressBar(max_value = len(IOCs)) as bar:
        iocs = [parse_attribute(ioc, crypto, bar, i) for (i,ioc) in enumerate(IOCs)]

    # Sort IOCs in different files for optimization
    printv("Sort IOCs with attributes")
	# The first case only happens when only using bloom filter (!=bloomy)
    try:
        if iocs[0]['joker']:
            iocDic['joker'] = [{'joker':True}] # (for bloom filter)
    except:
        for ioc in iocs:
            typ = "_".join(ioc["attributes"].split('||'))
            try:
                iocDic[typ].append(ioc)
            except:
                iocDic[typ] = [ioc]
    return iocDic

def store_rules(iocDic, conf=conf):
    printv("Store IOCs in files")
    for typ in iocDic:
        with open(conf['rules']['location'] + '/' + typ +'.tsv', 'wt') as output_file:
            dict_writer = csv.DictWriter(output_file, iocDic[typ][0].keys(), delimiter='\t')
            dict_writer.writeheader()
            dict_writer.writerows(iocDic[typ])


def get_file_rules(filename, conf):
	path = conf['rules']['location']+'/'+filename
	rules = list()
	if not os.path.exists(path):
		if printErr:
			print("path does not exist")
		return rules
	    
	with open(path, "r") as f:
		data = csv.DictReader(f, delimiter='\t')
		for d in data:
			rules.append(d)

	return rules

def get_iocDic(conf=conf):
	printv("Get existing rules")

	iocDict = {}
	filenames = os.listdir(conf['rules']['location'])
	for name in filenames:
		if name != 'metadata':
			attr_type = (name.split('.')[0]).split('_')[0]
			iocDict[attr_type] = get_file_rules(name, conf)

	return iocDict

########
# Main #
########
if __name__ == "__main__":
    ###################
    # Parse Arguments #
    ###################
    parser = argparse.ArgumentParser(description='Create an encrypted IOC \
            rule.')
    parser.add_argument('--misp', default='web',
            help='web (for web api);mysql (directly from mysql); res for the csv')
    parser.add_argument('--csvname', default='misp_events',
            help='Name of the csv in the res/ folder')
    parser.add_argument('-v', '--verbose',\
            dest='verbose', action='store_true',\
            help='Explain what is being done')
    args = parser.parse_args()
    
    # Clean up the rule folder
    printv("Clean rules folder")
    if os.path.exists(conf['rules']['location']):
        shutil.rmtree(conf['rules']['location'])
    os.mkdir(conf['rules']['location'])

    # Fill IOC list
    printv("Get IOCs from " + args.misp)
    if args.misp == 'web':
        ioc_web()
    elif args.misp == 'mysql':
        ioc_mysql()
    elif args.misp == 'res':
        ioc_csv()
    else:
        sys.exit('misp argument is miss configured. Please select web, res or mysql')

    # Choose crypto system
    crypto = Crypto(conf["rules"]["cryptomodule"], conf)

    # Parse IOCs
    iocDic = parsing(IOCs, crypto)
    store_rules(iocDic)
    

    # Create metadata (End function for Crypto modules)
    printv("Create metadata")
    crypto.save_meta()
else:
    def printv(val):
        pass