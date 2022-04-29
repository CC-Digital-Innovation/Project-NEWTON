import requests
import json
import datetime
import pymods.decisiontree.decisiontree as classify
from datetime import timedelta

#Define a class to hold relevent CVE data: ID, description, affected configs, cvss scores, resource links, etc
class CVE:
    def __init__(self):
        self.cveID = ""
        self.affects = []
        self.description = ""
        self.links = []
        self.cvss3 = ""
        self.cvss2 = ""
        self.quantified = [[]]
        self.actionable = bool
    def show_cve(self):
        print(f"cve ID: { self.cveID}\n")
        print(f"description: \n{ self.description}\n")
        print(f"Affected Devices:")
        for device in self.affects:
            print(f"{device}\n")
        print(f"Reference Links:")
        for link in self.links:
            print(f"{link}\n")
        print(f"CVSS 3 Score: {self.cvss3}")
        print(f"CVSS 2 Score: {self.cvss2}")
        print(f"Quantified: { self.quantified}")
        print(f"Actionable? {self.actionable}")



#CVE configurations sections consists of nodes with a children piece. This function accesses all possible children and thier CPE strings recursively
#NOTE: This needs attention. Right now I am pulling out all cpe strings where "vulnerability" is true, however I need to be accessing all cpe strings and saving the operator as well.
#NOTE cont: The "vulnerable" boolean just means the device isn't vulnerable by itself and must be paired with an AND operator meaning it must have one of the given software pieces installed to be vulnerable
#returns a list of cpe strings
def get_children(nodes, cpelist):
    cpes = {
    "cpe" : "",
    "versionEnd": ""
    }
    for node in nodes:
        for match in node["cpe_match"]:
            if match["vulnerable"]:
                cpes["cpe"]=match["cpe23Uri"]
                if "versionEndExcluding" in match:
                    cpes["versionEnd"]=(match["versionEndExcluding"])
                cpelist.append(cpes)
                cpes = {"cpe" : "",
                        "versionEnd": ""}
        if node["children"]:
            cpelist = get_children(node["children"],cpelist)
    
    return cpelist

#Takes a list of CPE strings cpe:CPEversion:letter?:Manufacturer:Model:version:*:*:*:*:*
#Splits the above format by : and saves manufacture, model and version info to a dictionary that is put into a list a dictionaries coorisponding to the list of cpes
#returns a list of dictionaries of affected configurations
def clean_cpes(cpelist):
    affects = []
    affdict = {}
    for cpe in cpelist:
        divide = cpe["cpe"].split(":")
        affdict["manufacturer"] = divide[3].replace("_", " ")
        affdict["Model"]= divide[4].replace("_", " ")
        affdict["Version"]=divide[5]
        affdict["VersionEnd"]=cpe["versionEnd"]
        affects.append(affdict)
        affdict={}
    return affects

#Rtrieves CVEs from the National Vulnerability Database API
#Right now it retrieves one timeframe, but if this goes live it will retrieve CVEs and classify them every 12 hours
#returns json formated results from api
def get_from_nvd():
    today = datetime.datetime.now()
    timerange = today- timedelta(hours = 48)
    todayfrmt=today.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-05:00")
    timerangefrmt = timerange.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-05:00")
    
    url = "https://services.nvd.nist.gov/rest/json/cves/1.0"

    parameters = {
        "modStartDate" : "2022-04-18T23:05:07:000 UTC-04:00",
        "modEndDate" :   "2022-04-27T23:05:07:000 UTC-04:00",
        "resultsPerPage" : 2000
    }

    r = requests.get(url, params = parameters)
    """with open("writeone.json", "r") as f:
        #f.write(json.dumps(r.json(), indent=4))
        read = f.read()
    raw = json.loads(read)"""
    raw = r.json()
    return raw["result"]["CVE_Items"]

#Looks at each cve in the list of filtered cve objects and compares each affected configuration's manufacturer with a list of manufacturers that we are interested in.
#Quantifies manufactureres we care about with a 1 and ones we don't with a 0
#Saves each quantified manufacturer in a list with the cvss score in the format [CVSS3,CVSS2,1 or 0] : [5.5,6.5,0]
def qunatify_Mans(cves):
    ManList = [ "cisco",
                "palo alto",
                "cloudgenix",
                "dell"
    ]

    ManRanks = []
    ManRank = []
    for cve in cves:
        for device in cve.affects:
            ManRanks.append(cve.cvss3)
            ManRanks.append(cve.cvss2)
            if device["manufacturer"] in ManList:
                ManRanks.append(1)
            else:
                ManRanks.append(0)
            ManRank.append(ManRanks)
            ManRanks=[]
        setattr(cve, "quantified", ManRank)
        ManRank=[]

#Takes raw results from NVD and filters data we want into a list of CVE objects
#Calls recursive function for configurations and cpe cleaner for list of dictionaries
def generate_cve_list():
    links =[]
    cves = []
    rawcves=get_from_nvd()
    for rawcve in rawcves:
        cve = CVE()
        cpelist = []
        setattr(cve, "cveID", rawcve["cve"]["CVE_data_meta"]["ID"])
        setattr(cve, "description", rawcve["cve"]["description"]["description_data"][0]["value"])
        cpes= get_children(rawcve["configurations"]["nodes"], cpelist)
        affects = clean_cpes(cpes)
        setattr(cve, "affects", affects)
        for data in rawcve["cve"]["references"]["reference_data"]:
            links.append(data["url"])
        setattr(cve, "links", links)
        links = []
        if rawcve["impact"]:
            if "baseMetricV3" in rawcve["impact"]:
                setattr(cve, "cvss3", rawcve["impact"]["baseMetricV3"]["impactScore"])
            if "baseMetricV2" in  rawcve["impact"]:
                setattr(cve, "cvss2", rawcve["impact"]["baseMetricV2"]["impactScore"])
        else:
            setattr(cve, "cvss3", None)
            setattr(cve, "cvss2", None)
        cves.append(cve)
    return cves


#Main function to coordinate function calls
#Generates list of CVE objects
#Creates decision tree from decisiontree.py
#Runs predictions on Actionable variable based on Quantified values
#Currently writes results to a file for easy searching and confirmation of decistion tree predictions
#TODO: Save Actionable CVES to database
#TODO: Search through CMDB for configurations that match CVE configurations
#TODO: Email matching list of configs with email api
def main():
    cves = generate_cve_list()
    qunatify_Mans(cves)
    CVEclassifier = classify.train_tree()
    for cve in cves:
        if cve.affects and cve.cvss3 and cve.cvss2:
            predictions = classify.predict(CVEclassifier, cve.quantified)
            if 1 in predictions:
                setattr(cve, "actionable", True)
            else:
                setattr(cve, "actionable", False)
        else:
            setattr(cve, "actionable", False)

    with open("writeresults.txt", "w") as f:
        for cve in cves:
            f.write(f"""
            cveID: {cve.cveID}
            affects:
            {cve.affects}
            Quantified:
            {cve.quantified}
            Actionable? {cve.actionable}
            """)


if __name__ == "__main__":
    main()



