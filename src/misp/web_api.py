#!/usr/bin/env python
# -*- coding: utf-8 -*-

from configuration import Configuration
import requests
import json
import os, shutil

conf = Configuration()

# update false positive list : https://github.com/MISP/misp-warninglists
# and get updated values
def save_json(url, name, remove_point=False, add_www=False):
    req = requests.get(url)
    l = req.json()['list']
    l = [val.lower() for val in l]
    if remove_point:
        list2 = [val[1:] for val in l if val.startswith('.')]
        list2.extend([val for val in l if not val.startswith('.')])
        l = list2
    if add_www:
        list2 = ['www.%s' % val for val in l]
        l.extend(list2)
    json_list = {'list': l}
    with open('res/{}.json'.format(name), 'w+') as f:
        json.dump(json_list, f)

    
def update():
    # first let clean the ressources
    if os.path.exists("../res"):
        shutil.rmtree("../res")
    os.mkdir("../res")
    
    # get misp data in csv
    session = requests.Session()
    session.verify = True
    session.proxies = None

    header = {}
    header['Authorization'] = conf['misp']['token']
    session.headers.update(header)

    # Change to csv (only download ids elements!)
    events = session.get('{}events/csv/download/'.format(conf['misp']['url']))

    with open('../res/misp_events.csv', 'w') as f:
        f.write(events.text)

if __name__ == "__main__":
    update()
