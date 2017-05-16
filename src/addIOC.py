#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
	Once already read the misp implementation, sometimes, we only need to add additionnal element.
	This is really usefull for a high number of iterations

	This implementation could have been done directly in readMisp but I want to avoid misinterpretation
	or to add too many arguments that can be modified by others
		=> Here NO RULES are removed when running, the only action is to add some
			from res or from the form
"""
import sys
import os

# MISP import
from configuration import Configuration
from readMisp import create_message, parse_attribute, get_iocDic, parsing as readMisp_parsing, store_rules
from misp.web_api import get_IOCs_update

# Tools import
import argparse
import configparser
import csv
import datetime
from progressbar import ProgressBar

# Crypto import
from crypto.choose_crypto import Crypto

args = {}
###########
# Helpers #
###########
def printv(value):
    if args.verbose:
        print(value)


def askContinue():
	res = input('Do you want to add more IOCs? (yes|No): ').lower()
	if 'yes' in res:
		return True
	else:
		return False


##################
# Implementation #
##################
IOCs = list()
conf = Configuration()


def ioc_csv(filename):
	iocList = []
	printv('Get new IOCs')
	if '.csv' not in filename:
		filename += '.csv'
	with open('../res/' + filename, 'r') as f:
		data = csv.DictReader(f)
		for d in data:
			iocList.append(d)
	return iocList

def ioc_arg():
	print("Pay attention that no check are make on the inputs")
	ioc = {}
	ioc['id'] = input('id*: ')
	ioc['event_id'] = input('event id*: ')
	ioc['category'] = input('category*: ')
	ioc['type'] = input('type*: ')
	v1 = input('value1*:')
	v2 = input('value2:')
	value = v1
	if v2 != '':
		value += '|' + v2
	ioc['value'] = value
	ioc['to_ids'] = -1
	while ioc['to_ids'] not in [0, 1]:
		try:
			ioc['to_ids'] = int(input('to_ids*(1|0): '))
		except:
			print("Value must be either 0 or 1")
	ioc['uuid'] = input('uuid*: ')
	ok = False
	while not ok:
		try:
			ioc['date'] = datetime.datetime.fromtimestamp(int(input('timestamp*: '))).strftime("%Y%m%d")
			inp = input('distribution: ')
			if inp != '':
				ioc['distribution'] = int(inp)
			inp = input('sharing group id: ')
			if inp != '':
				ioc['sharing_group_id'] = int(inp)
			ok = 1
		except:
			print('timestamp, distribution and sharing group id must be integers')

	if ioc['to_ids']==1:
		IOCs.append(ioc)

def updateRes():
	# date must be like 2015-02-15
	# first get oldIOCs in clear
	printv('Get new IOCs since')
	updateFileName = get_IOCs_update()

	return ioc_csv(updateFileName)

def create_ioc_lines(rowNames, TypedIOCList):
	lines = []
	for ioc in TypedIOCList:
		lines.append('\t'.join([ioc[row] for row in rowNames]))
	return '\n' + '\n'.join(lines)

def saveIOCs():
	#TODO !!!!!! remove rules and meta beforehand 
	#TODO implement a check if the values already in (argument pour désactiver)
	metaParser = configparser.ConfigParser()
	try:
		metaParser.read(conf['rules']['location'] + '/metadata')
		metadata = metaParser._sections
	except:
		print('Rules must have already been created for adding news')
		sys.exit(1)
	os.remove(conf['rules']['location'] + '/metadata')

	crypto = Crypto(conf["rules"]["cryptomodule"], conf, metadata)

	ruleFiles = {}
	for name in os.listdir(conf['rules']['location']):
		ruleFiles[(name.split('.')[0]).split('_')[0]] = name

	# create a dico of rules
	iocDic = readMisp_parsing(IOCs, crypto)

	# For each type add to file if exist
	iocNewType = {}
	bar = ProgressBar()
	for iocType in bar(iocDic.keys()):
		# exist rules of the same type
		try:
			filename = ruleFiles[iocType]
			with open(filename, 'r') as f:
				rowsNames = f.readline().split('\t')

			iocLines = create_ioc_lines(rowsNames, iocDic[iocType])
			with open(filename, 'a') as f:
				f.write(ioLines)
		except:
			iocNewType[iocType] = iocDic[iocType]
	
	if len(iocNewType) > 0:
		store_rules(iocDic, conf)

	# ReSave metaparameter important for bloom filters
	printv("Rewrite metadata")
	crypto.save_meta()



if __name__ == '__main__':
	###################
	# Parse Arguments #
	###################

	parser = argparse.ArgumentParser(description='Add new rules to already generated ones.')
	parser.add_argument('--misp', default='args',
	        help='form for filling the form OR res to get data from res in a CSV file')
	parser.add_argument('--CSVname', default='addIOCs',
	        help='Name of the CSV in the res/ folder (Without .csv)')
	parser.add_argument('-v', '--verbose',\
	        dest='verbose', action='store_true',\
	        help='Explain what is being done')
	parser.add_argument('-u', '--updateRes',\
	        dest='updateRes', action='store_true',\
	        help='Download new IOCs from misp web api and then, compare with old res to create the new rules')
	args = parser.parse_args()

	"""Let's go!"""
	if args.updateRes:
		IOCs = updateRes()
	elif args.misp == 'args':
		cont = True
		while cont:
			ioc_arg()
			cont = askContinue()
	elif args.misp == 'res':
		IOCs = ioc_csv(args.CSVname)
	else:
		print("Choose a correct argument for misp")
	print(len(IOCs))
	saveIOCs()
