import configparser
import pysnow
import os
import requests
from fastapi.params import Query, Body, Form
from pydantic.types import FilePath
from fastapi import FastAPI
from loguru import logger

#Set globals and pull data from config file
app = FastAPI()

config = configparser.ConfigParser()
CWD = os.getcwd()
configDir = os.path.join(CWD, "Config")
configPath = os.path.join(configDir, "config.ini")
config.read(configPath)
USER = config.get('snow', 'api_user')
PASS = config.get('snow', 'api_password')
INSTANCE = config.get('snow', 'snow_instance')
snow_client = pysnow.Client(instance = INSTANCE, user = USER, password = PASS)


#Define a get function for the api based on model number, manufacturer and version
@app.get("/models/")
def get_matching_devices(   token: str = Form(...),
                            modelNum: str = Form(None),
                            manufacturer: str = Form(None),
                            modelNumsList: list = Form(None),
                            manufacturerList: list = Form(None)):
    #Authenticate with token in config                        
    if token == config.get('tokens', 'api_token'):
        table = snow_client.resource(api_path='/table/cmdb_ci')
        print(manufacturerList)
        print(modelNumsList)
        if (modelNumsList and manufacturerList) and len(modelNumsList)==len(manufacturerList):
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
            #Query and return devices that match
            RPquery = eval(f"(pysnow.QueryBuilder(){stringQuery})")
            fetch = table.get(query=RPquery).all()
            slimmedDevices = []
            for device in fetch:
                slim = {}
                slim["Device Name"] = device['name']
                slim["Model"] = device['model_number']
                slim["Customer"] = device['company']
                slimmedDevices.append(slim)
            return slimmedDevices
        elif (modelNum and manufacturer) and not (modelNumsList and manufacturerList):
            RPquery = (pysnow.QueryBuilder()
            .field('model_number').contains(modelNum)
            .AND()
            .field('manufacturer').contains(manufacturer)
            .AND()
            .field('operational_status').equals('1')
            )
            fetch = table.get(query=RPquery).all()
            slim = {}
            slimmedDevices = []
            for device in fetch:
                slim["Device Name"] = device['name']
                slim["Model"] = device['model_number']
                slim["Customer"] = device['company']
                slimmedDevices.append(slim)
            return slimmedDevices
        else:
            return {
                "Msg" : "Please send matching model number(s) and manufacturer(s)"
            }

    else:
        return {
            'Alert' : 'You are not authorized to access this content'
        }
