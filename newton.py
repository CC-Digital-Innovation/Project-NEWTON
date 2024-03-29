import datetime
import json
import sys
import logging
import configparser
import os
from loguru import logger
from datetime import timedelta
import pymods.decisiontree.decisiontree as classify
import pymods.nvd as nvd
import pymods.search as search
import pymods.emailReporter as email
import pymods.noco as dbsave


#Main function to coordinate function calls
#Generates list of CVE objects
#Creates decision tree from decisiontree.py
#Runs predictions on Actionable variable based on Quantified values
#Currently writes results to a file for easy searching and confirmation of decistion tree predictions
#TODO: Save Actionable CVES to database
#Done: Search through CMDB for configurations that match CVE configurations
#TODO: Email matching list of configs with email api

TODAY = datetime.datetime.now()
config = configparser.ConfigParser()
CWD = os.getcwd()
configDir = os.path.join(CWD, "Config")
configPath = os.path.join(configDir, "config.ini")
config.read(configPath)

@logger.catch
def begin_logs(sysname = None, sysport = None):
    logger.info("-----------------------------------------------------------------------------------")
    logger.info(f"Starting a log on {TODAY}")
    if sysname and sysport:
        logger.info(f"Server logging is on and logging to {sysname}:{sysport}")
    logger.info("-----------------------------------------------------------------------------------")

#Initialize logger and logs, individual log levels for various log locations
@logger.catch
def init_logs():
    logger.remove()
    logger.debug('setting console log')
    logger.add(sys.stderr, colorize=True, level="DEBUG")
    if "Logging" in config.sections():
        sysname = config.get('Logging', 'SyslogName')
        sysport = config.get('Logging', 'SyslogPort')
        if sysname and sysport:
            syslog = logging.handlers.SysLogHandler(address =(str(sysname), int(sysport)))
            logger.add(syslog)
            logger.enable("")
            begin_logs(sysname, sysport)
    else:
        begin_logs()


@logger.catch
def main():
    init_logs()
    timerange = TODAY- timedelta(hours = 12)
    enddate = TODAY.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-05:00")
    startdate   = timerange.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-05:00")
    logger.info(f"Getting Critical Vulnerabilities from National Vulnerability Database")
    logger.info(f"From: {startdate}")
    logger.info(f"To: {enddate}")
    raw = nvd.get_from_nvd(startdate, enddate)

    #Call mods to filter data
    logger.info("Beggining to filter CVE data")
    cves = nvd.generate_cve_list(raw)
    logger.info("Quantifying data for decision tree")
    nvd.qunatify_Mans(cves)
    
    #Spin up and train Decision Tree
    logger.info("Initializing Decision Tree Classifier")
    CVEclassifier = classify.train_tree()
    
    #Use tree to classify CVEs
    logger.info("Using classifier to determine cve impact on our systems")
    for cve in cves:
        logger.info(f"Classifying cve: {cve.cveID}")
        if cve.affects and (cve.cvss3 or cve.cvss2):
            predictions = classify.predict(CVEclassifier, cve.quantified)
            if 1 in predictions:
                setattr(cve, "actionable", True)
                logger.info(f"Actionable?: {cve.actionable}")
            else:
                setattr(cve, "actionable", False)
                logger.info(f"Actionable?: {cve.actionable}")
        else:
            setattr(cve, "actionable", False)
            logger.info(f"Actionable?: Not enough data in CVE")
    
    #pull current cves in db for redundancy check
    currentcves = dbsave.querycolumnlist("CVEID", "Active_CVES")

    #Take action on actionable CVEs
    logflag = True
    for cve in cves:
        if cve.actionable:
            logflag = False
            logflagdevs=True
            logger.info(f"Searching CMDB for impacted devices and sending email for {cve.cveID}")
            devs = search.cmdb(cve)
            if devs:
                logflagdevs=False
                reportName = f"Alert for: {cve.cveID}"
                subject    = f"Level 1 Vulnerability alert: {cve.cveID}"
                tableTitle = "Potentially Affected Devices"
                body = f"""
                {cve.cveID}
                {cve.description}
                CVSS Score 3: {cve.cvss3}
                CVSS Score 2: {cve.cvss2}
                """
                for link in cve.links:
                    body=body+link+"\n"
                with open ("deviceData.json", "w") as f:
                    f.write(json.dumps(devs))
                logger.info("Sending level 1 email")
                r = email.report(reportName, tableTitle,"deviceData.json", body, subject)
                logger.info(f"EmailAPI responded with {r}")
                #save to noco with redudancy checks
                if cve.cveID not in currentcves:
                    logger.info(f"{cve.cveID} not in Database, saving data")
                    cvedata = {
                            "CVEID" : cve.cveID,
                            "Description": cve.description,
                            "CVSS3": cve.cvss3,
                            "CVSS2": cve.cvss2,
                            "Active": 1
                    }
                    cvedata["Links"]=json.dumps(cve.links)
                    cveid = dbsave.insert(cvedata, "Active_CVES")
                    currentdevs = dbsave.querycolumnlist("DevName", "Affected_Devices")
                    for device in devs:
                        if device["Device Name"] not in currentdevs:
                            logger.info("device not in db, adding record")
                            devdata = {
                                    "DevName": device["Device Name"],
                                    "DevModel": device["Model"],
                                    "DevCustomer": device["Customer"]
                            }
                            devid = dbsave.insert(devdata, "Affected_Devices")
                            dbsave.insertm2m(devid, cveid, "Affected_Devices", "Active_CVES")
                        else:
                            logger.info("device in db, updated record")
                            devid = dbsave.queryOne("id", f"(DevName,eq,{device['Device Name']})", "Affected_Devices")["id"]
                            response= dbsave.insertm2m(devid, cveid, "Affected_Devices", "Active_CVES")
                            logger.debug(f"result: {response}")
                else:
                    logger.info(f"{cve.cveID} already saved in DB")
                    #TODO: check for updates

                #TODO: Create Snow incidents
            if logflagdevs:
                logger.info(f"No devices found in CMDB for {cve.cveID}")
    if logflag:
        logger.info("No actionable CVEs today")
    logger.info(f"Newton Run complete")
    logger.info("___________________________________________________________________________________")

        

if __name__ == "__main__":
    main()
