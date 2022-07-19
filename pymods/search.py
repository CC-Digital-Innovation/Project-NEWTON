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
    stringQuery = ""
    for modelNum, man in zip(modelNumsList, manufacturerList):
        stringQuery = stringQuery + f"""
        .field('model_number').contains("{modelNum}")
        .AND()
        .field('manufacturer').contains("{man}")
        .AND()
        .field('operational_status').equals('1')
        .NQ()"""
    stringQuery = stringQuery.strip(".NQ()")
    stringQuery = stringQuery.strip("\n")
    #Query and return devices that match TODO: Find a way to not use eval
    RPquery = eval(f"(pysnow.QueryBuilder(){stringQuery})")
    fetch = table.get(query=RPquery).all()
    slimmedDevices = []
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
    for affect in cve.affects:
        num = re.search("[0-9]+", affect["Model"])
        if num and len(num.group())>2:
            models.append(num.group())
            mans.append(affect["manufacturer"])
    if models and mans:
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