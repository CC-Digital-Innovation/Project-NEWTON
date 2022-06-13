import datetime
import json
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

def main():
    today = datetime.datetime.now()
    timerange = today- timedelta(hours = 12)
    startdate = today.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-05:00")
    enddate   = timerange.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-05:00")

    startdate =   "2021-10-06T23:05:07:000 UTC-04:00"
    enddate   =   "2021-10-07T23:05:07:000 UTC-04:00"
    logger.info(f"Getting Critical Vulnerabilities from National Vulnerability Database")
    logger.info(f"From: {startdate}")
    logger.info(f"To: {enddate}")
    raw = nvd.get_from_nvd(startdate, enddate)
    input("Vulnerabilities retrieved, press enter to continue")
    logger.info("Beggining to filter CVE data")
    cves = nvd.generate_cve_list(raw)
    logger.info("Quantifying data for decision tree")
    nvd.qunatify_Mans(cves)
    input("CVEs filetered and quantified, press enter to continue")
    logger.info("Initializing Decision Tree Classifier")
    CVEclassifier = classify.train_tree()
    input("Decision tree initialized, press enter to process cves")
    logger.info("Using classifier to determine cve impact on our systems")
    for cve in cves:
        logger.info(f"Classifying cve: {cve.cveID}")
        if cve.affects and cve.cvss3 and cve.cvss2:
            predictions = classify.predict(CVEclassifier, cve.quantified)
            if 1 in predictions:
                setattr(cve, "actionable", True)
                logger.info(f"Actionable?: {cve.actionable}")
            else:
                setattr(cve, "actionable", False)
                logger.info(f"Actionable?: {cve.actionable}")
        else:
            setattr(cve, "actionable", False)
    input("predictions complete, press enter to search CMDB")
    for cve in cves:
        if cve.actionable and cve.cveID != "CVE-2020-3428":
            logger.info(f"Searching CMDB for impacted devices and sending email for {cve.cveID}")
            devs = search.cmdb(cve)
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
            #r = email.report(reportName, tableTitle,"deviceData.json", body, subject)
            #Do a pull from db and check for redundancy
            dbsave.insert(cve, devs)

        

if __name__ == "__main__":
    main()
