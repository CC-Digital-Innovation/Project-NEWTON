import re
import os
import requests
import pysnow
from requests.auth import HTTPBasicAuth
import configparser
from loguru import logger


cwd = os.getcwd()
configdir = os.path.join(cwd, "Config")
configPath = os.path.join(configdir, "config.ini")
config = configparser.ConfigParser()
config.read(configPath)
#URL = config.get('urls', 'cmdb_api')
#TOKEN = config.get("tokens", "cmdb_api_token")
USER = config.get('snow', 'api_user')
PASS = config.get('snow', 'api_password')
INSTANCE = config.get('snow', 'snow_instance')
snow_client = pysnow.Client(instance = INSTANCE, user = USER, password = PASS)
TABLE = snow_client.resource(api_path='/table/cmdb_ci')


@logger.catch
def get_value(link, value):
    r = requests.get(link, auth = HTTPBasicAuth(USER, PASS))
    return r.json()['result'][value]

@logger.catch
def get_matching_devices(modelNumsList,manufacturerList):
    #Authenticate with token in config                        
    query = pysnow.QueryBuilder()
    zipped = list(zip(modelNumsList, manufacturerList))
    flag = False
    count = 0
    fetched = []
    for modelNum, man in zipped:
        for part in modelNum:
            if any(modchar.isdigit() for modchar in part):
                if flag:
                    query.NQ()
                query.field('manufacturer').contains(man).AND()
                query.field('model_number').contains(part).OR()
                query.field('model_id').contains(part)
                flag = True
                count = count + 1
                break
        if count == 50:
            count = 0
            fetch = TABLE.get(query=query).all()
            fetched.append(fetch)
            query = pysnow.QueryBuilder()
            flag = False
    #Query and return devices that match
    if flag:
        fetch = TABLE.get(query=query).all()
        fetched.append(fetch)
    slimmedDevices = []
    for fetch in fetched:
        for device in fetch:
            slim = {}
            slim["Device Name"] = device['name']
            if device['model_number']:
                slim["Model"] = device['model_number']
            elif device["model_id"]:
                slim["Model"] = device['model_id']
            slim["Customer"] = get_value(device['company']['link'], 'name')
            slimmedDevices.append(slim)
    return slimmedDevices


@logger.catch
def cmdb(cve):
    action_devices= []
    models =[]
    mans = []
    param= {}
    if cve.affects:
        for affect in cve.affects:
            modParts = affect["Model"].split("_")
            models.append(modParts)
            mans.append(affect["manufacturer"])  
        devices = get_matching_devices(models, mans)
        """param = {
            "token" : TOKEN,
            "modelNumsList" : models,
            "manufacturerList" : mans
            }
        r = requests.get(URL, data = param)
        test = r.json()"""
        for result in devices:
            action_devices.append(result)
        logger.info(f"Number of matching model numbers in cmdb for {cve.cveID}: {len(action_devices)}")


    return action_devices