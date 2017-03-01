#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser

def Configuration():
    configParser = configparser.ConfigParser()
    configParser.read('../conf/configuration')
    return configParser._sections

