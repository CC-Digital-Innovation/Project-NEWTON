import configparser
import os
import json
import requests

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

def queryOne(fields, where, table):
    query = {
        'fields' : fields,
        'where'  : where
    }
    sr = requests.get(f"{url}{table}", headers=header, params=query)
    results = sr.json()
    result = results[0]
    return result

def insert(cve, affectedlist):
    query = {
            "CVEID" : cve.cveID,
            "Description": cve.description,
            "CVSS3": cve.cvss3,
            "CVSS2": cve.cvss2,
            "Active": 1
    }
    query["Links"]=cve.links
    r = requests.request("POST", f"{url}Active_CVES", headers=header, data=json.dumps(query))
    dbcveID = r.json()["id"]
    for device in affectedlist:
        query2 = {
                "DevName": device["Device Name"],
                "DevModel": device["Model"],
                "DevCustomer": device["Customer"]
        }
        r2 = requests.post(f"{url}Affected_Devices", headers=header, data=json.dumps(query2))
        query3 = {
            "table1_id": r2.json()['id']
        }
        r3 = requests.post(f"{url}Active_CVES/{dbcveID}/m2mAffected_Devices_Active_CVES", headers=header, data=json.dumps(query3))