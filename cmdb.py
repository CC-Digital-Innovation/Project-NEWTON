import configparser
import pysnow
import os
import requests
from fastapi.params import Query
from pydantic.types import FilePath
from fastapi import FastAPI

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
def get_matching_devices(   token: str = Query(...),
                            modelNum: str = Query(...),
                            version: str = Query(None)):
    #Authenticate with token in config                        
    if token == config.get('tokens', 'api_token'):
        #Query and return devices that match
        table = snow_client.resource(api_path='/table/cmdb_ci')
        RPquery = (
            pysnow.QueryBuilder()
            .field('model_number').contains(modelNum)
            .AND()
            .field('operational_status').equals('1')
        )
        fetch = table.get(query=RPquery).all()
        return fetch
    else:
        return {
            'Alert' : 'You are not authorized to access this content'
        }
