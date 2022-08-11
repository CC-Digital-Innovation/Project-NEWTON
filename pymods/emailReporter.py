import configparser
import os
import requests
from loguru import logger

config = configparser.ConfigParser()
CWD = os.getcwd()
configDir = os.path.join(CWD, "Config")
configPath = os.path.join(configDir, "config.ini")
config.read(configPath)

@logger.catch
def report(reportName, tableTitle, filepath, body, subject):
    #Production or testing
    URL = config.get('urls', 'email_api')

    Data = {
        'Token'       : config.get('tokens', 'email_api_token'),
        'ID'          : config.get('EmailAPIData', 'ID'),
        'to'          : config.get('EmailAPIData', 'recipients'),
        'cc'          : config.get('EmailAPIData', 'cc'),
        'bcc'         : config.get('EmailAPIData', 'bcc'),
        'subject'     : subject,
        'body'        : body,
        'report_name' : reportName,
        'table_title' : tableTitle
    }
    with open(filepath, "rb") as file:
        uploadFile = {'files' : file}
        logger.info(f"sending email to {Data['to']} and {Data['cc']}")
        return requests.post(url = URL, data = Data, files = uploadFile)
    