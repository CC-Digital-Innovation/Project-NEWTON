import re
import os
import requests
import configparser
from loguru import logger


cwd = os.getcwd()
configdir = os.path.join(cwd, "Config")
configPath = os.path.join(configdir, "config.ini")
config = configparser.ConfigParser()
config.read(configPath)
URL = config.get('urls', 'cmdb_api')
TOKEN = config.get("tokens", "cmdb_api_token")

def cmdb(cve):
    action_devices= []
    models =[]
    mans = []
    param= {}
    for affect in cve.affects:
        num = re.search("[0-9]+", affect["Model"])
        if num and len(num.group())>2:
            models.append(num.group())
            mans.append(affect["manufacturer"])
    param = {
        "token" : TOKEN,
        "modelNumsList" : models,
        "manufacturerList" : mans
        }
    r = requests.get(URL, data = param)
    test = r.json()
    for result in test:
        action_devices.append(result)
    logger.info(f"Number of matching model numbers in cmdb for {cve.cveID}: {len(action_devices)}")

    return action_devices