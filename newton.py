import datetime
import re
import sys
import requests
from loguru import logger
from datetime import timedelta
import pymods.decisiontree.decisiontree as classify
import pymods.nvd as nvd




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

    logger.info("Beggining to filter CVE data")
    cves = nvd.generate_cve_list(raw)
    logger.info("Quantifying data for decision tree")
    nvd.qunatify_Mans(cves)
    logger.info("Initializing Decision Tree Classifier")
    CVEclassifier = classify.train_tree()
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
    logger.info("Searching CMDB for impacted devices")
    ogstdout= sys.stdout
    action_devices= []
    with open("writeresults.txt", "w") as f:
        url= "http://127.0.0.1:8000/models/"
        for cve in cves:
            sys.stdout = f
            cve.show_cve()
            sys.stdout = ogstdout
            if cve.actionable:
                models =[]
                mans = []
                param= {}
                for affect in cve.affects:
                    num = re.search("[0-9]+", affect["Model"])
                    if num and len(num.group())>2:
                        models.append(num.group())
                        mans.append(affect["manufacturer"])
                param = {
                    "token" : "xzy9WB4mMhybmpgIEmeyyI1ItIPJmHqjF5D4weKH4RbkWgZv183vafs3wdhg",
                    "modelNumsList" : models,
                    "manufacturerList" : mans
                    }
                r = requests.get(url, data = param)
                test = r.json()
                for result in test:
                    action_devices.append(result)
                logger.info(f"Number of matching model numbers in cmdb for {cve.cveID}: {len(action_devices)}")
                f.write(f"""
                Number of devices found : {len(action_devices)}
                """)
                for device in action_devices:
                    f.write(f"""
                    {device}
                    """)


if __name__ == "__main__":
    main()
