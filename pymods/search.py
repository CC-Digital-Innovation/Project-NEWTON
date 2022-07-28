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

def get_value(link, value):
    r = requests.get(link, auth = HTTPBasicAuth(USER, PASS))
    return r.json()['result'][value]

def get_matching_devices(modelNumsList,manufacturerList):
    #Authenticate with token in config                        
    table = snow_client.resource(api_path='/table/cmdb_ci')
    slimmedDevices = []
    query = pysnow.QueryBuilder()
    zipped = list(zip(modelNumsList, manufacturerList))
    flag = False
    for modelNum, man in zipped:
        for part in modelNum:
            if any(modchar.isdigit() for modchar in part):
                if flag:
                    query.NQ()
                query.field('manufacturer').contains(man).AND()
                query.field('model_number').contains(part).OR()
                query.field('model_id').contains(part)
                flag = True
                break
    #Query and return devices that match
    print(len(str(query)))
    fetch = table.get(query=query).all()
    for device in fetch:
        slim = {}
        slim["Device Name"] = device['name']
        slim["Model"] = device['model_number']
        slim["Customer"] = get_value(device['company']['link'], 'name')
        slimmedDevices.append(slim)
    return slimmedDevices



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
            """num = re.search("[0-9]+", affect["Model"])
            if num and len(num.group())>2:
                models.append(num.group())
                mans.append(affect["manufacturer"])"""
        test = get_matching_devices(models, mans)
        """param = {
            "token" : TOKEN,
            "modelNumsList" : models,
            "manufacturerList" : mans
            }
        r = requests.get(URL, data = param)
        test = r.json()"""
        for result in test:
            action_devices.append(result)
        logger.info(f"Number of matching model numbers in cmdb for {cve.cveID}: {len(action_devices)}")


    return action_devices