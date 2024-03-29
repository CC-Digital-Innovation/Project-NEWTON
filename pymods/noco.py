import configparser
import os
import json
import requests
from loguru import logger

config = configparser.ConfigParser()
CWD = os.path.dirname(os.path.dirname(__file__))
configDir = os.path.join(CWD, "Config")
configPath = os.path.join(configDir, "config.ini")
config.read(configPath)
noCoAuth = config.get('tokens', 'noco_token')

header = {
        'xc-auth': noCoAuth,
        'Content-Type': 'application/json'
}
url = noCoAuth = config.get('urls', 'noco_base')

@logger.catch
def queryOne(fields, where, table):
    query = {
        'fields' : fields,
        'where'  : where
    }
    sr = requests.get(f"{url}{table}", headers=header, params=query)
    results = sr.json()
    logger.info(results)
    result = results[0]
    return result

@logger.catch
def querycolumnlist(column, table):
    query = {
        'column_name': column
    }
    sr = requests.get(f"{url}{table}/groupby", headers=header, params=query)
    results = sr.json()
    current = []
    for stored in results:
        current.append(stored[column])
    return current

@logger.catch
def insert(data, table):
    r = requests.request("POST", f"{url}{table}", headers=header, data=json.dumps(data))
    logger.info(r.json())
    return r.json()["id"]     

@logger.catch        
def insertm2m(t1id, t2id, table1, table2):
    query = {
        "table1_id": t1id
    }
    r3 = requests.post(f"{url}Active_CVES/{t2id}/m2m{table1}_{table2}", headers=header, data=json.dumps(query))
    logger.info(r3.json())
    return r3.json()