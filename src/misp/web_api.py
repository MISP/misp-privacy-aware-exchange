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

    
def get_IOCs():
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
    lastDate = events.text[-9:-1]
    lastDate = lastDate[0:4]+ '-' + lastDate[4:6]+ '-' + lastDate[6:]

    # TODO create a metafile with the data of the last event
    if os.path.exists('../res/metadata'):
        os.remove('../res/metadata')

    with open('../res/metadata', 'w') as f:
        f.write(lastDate)


def get_IOCs_update():
    # date must be formated like 2015-02-15
    # get last date:
    with open('../res/metadata', 'r') as f:
        lastDate = f.read()[-11:]
    if (lastDate[-1] == '\n'):
        lastDate = lastDate[:-1]
    else:
        lastDate = lastDate[-10:]

    # get misp data in csv
    session = requests.Session()
    session.verify = True
    session.proxies = None

    header = {}
    header['Authorization'] = conf['misp']['token']
    session.headers.update(header)

    # Change to csv (only download ids elements!)
    events = session.get('{}events/csv/download/false/false/false/false/false/false/{}////'.format(conf['misp']['url'], lastDate))
    
    count = 0
    for i in os.listdir('../res/'):
        if 'update' in i:
            count += 1
    filename = 'update' + str(count)  

    # Write to metafile
    lastDate = events.text[-9:-1]
    try:
        i = int(lastDate) # must be int
        with open('../res/' + filename + '.csv', 'w') as f:
            f.write(events.text)
        lastDate = lastDate[0:4]+ '-' + lastDate[4:6]+ '-' + lastDate[6:]
        with open('../res/metadata', 'a') as f:
            f.write('\n' + lastDate)
    except:
        pass
    return filename

def get_new_IOCs():
    # TODO implement
    # get last date in metafile
    # get last :)
    pass

if __name__ == "__main__":
    update()
