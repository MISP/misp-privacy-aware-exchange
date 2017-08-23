#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This script is used to manipulate the configuration file
"""
import configparser

# Get configuration
def Configuration():
    configParser = configparser.ConfigParser()
    configParser.read('../conf/configuration')
    return configParser._sections

# Copy configuration
def configurationSave():
    with open('../conf/configuration', 'r') as f:
        with open('../conf/configurationBak', 'w') as w:
            w.write(f.read())

# Restore configuration to the last copy
def configurationReset():
    with open('../conf/configurationBak', 'r') as f:
        with open('../conf/configuration', 'w') as w:
            w.write(f.read())

# Modify a value
def configSet(section, subsection, value, configFile='../conf/configuration'):
    configParser = configparser.ConfigParser()
    configParser.read(configFile)
    configParser[section][subsection] = str(value)
    with open(configFile, 'w') as configFile:
        configParser.write(configFile)


