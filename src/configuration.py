#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser

def Configuration():
    configParser = configparser.ConfigParser()
    configParser.read('../conf/configuration')
    return configParser._sections

def configurationSave():
    with open('../conf/configuration', 'r') as f:
        with open('../conf/configurationBak', 'w') as w:
            w.write(f.read())

def configurationReset():
    with open('../conf/configurationBak', 'r') as f:
        with open('../conf/configuration', 'w') as w:
            w.write(f.read())

def configSet(section, subsection, value, configFile='../conf/configuration'):
    configParser = configparser.ConfigParser()
    configParser.read(configFile)
    configParser[section][subsection] = str(value)
    with open(configFile, 'w') as configFile:
        configParser.write(configFile)


