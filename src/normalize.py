#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Do not duplicate code in both readMisp and match Rules !
The goal is first to normalize URLs and IPv6 addresses
URLs:
    - standards normalization as done with the library
    - additionnal 'normalization' steps explained in the report
        (could transform the URL but better for matching)
IPv6: 
    - # TODO 
"""
import re, urllib
from url_normalize import url_normalize
from ipaddress import ip_address, ip_network


def normalize(ioc):
    for attr_type in ioc:
        # url|uri|link are often misused
        # Thus they are considered to be the same
        if attr_type == 'url' or\
            attr_type == 'uri' or\
            attr_type == 'link':
                # just solve one specific case:
                if not '..org' in ioc[attr_type]:
                    ioc[attr_type] = urlNorm(ioc[attr_type])
        elif attr_type == 'hostname':
                ioc[attr_type] = ioc[attr_type].lower()
        elif 'ip-' in attr_type:
            ioc[attr_type] = ipNorm(ioc[attr_type])
    return ioc


def ipNorm(ip):
    # This normalize IPv6
    try:
        if '/' in ip:
            return str(ip_network(ip))
        else:
            return str(ip_address(ip))
    except:
        print('IP normalisation raised an error with this ip ' + ip)
        return ip

directory_indexes = ['default.asp', 'index.html', 'index.php', 'index.shtml'\
                    'index.jsp', '\?']
def urlNorm(url):
    url = url_normalize(url)
    # removes fragment
    url = urllib.parse.urldefrag(url)[0]

    # remove index directories if it is at the end
    for index in directory_indexes:
        url = re.sub(index+ '$', '', url)
    
    # remove http https and www.
    url = re.sub("^https?://(www.)?", '', url)
    return url
