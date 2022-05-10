import requests
from loguru import logger

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
        print(f"Actionable? {self.actionable}\n")



#CVE configurations sections consists of nodes with a children piece. This function accesses all possible children and thier CPE strings recursively
#NOTE: This needs attention. Right now I am pulling out all cpe strings, however I need to be accessing all cpe strings and saving the operator as well.
#NOTE cont: The "vulnerable" boolean just means the device isn't vulnerable by itself and must be paired with an AND operator meaning it must have one of the given software pieces installed to be vulnerable
#returns a list of cpe strings
def get_children(nodes, cpelist):
    cpes = {
    "cpe" : "",
    "versionEnd": ""
    }
    for node in nodes:
        for match in node["cpe_match"]:
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
def get_from_nvd(startdate, enddate):
    
    url = "https://services.nvd.nist.gov/rest/json/cves/1.0"

    parameters = {
        "modStartDate" : startdate,
        "modEndDate" :   enddate,
        "resultsPerPage" : 2000
    }

    r = requests.get(url, params = parameters)
    logger.info(f"Response from NVD: {r}")
    raw = r.json()
    return raw["result"]["CVE_Items"]

#Looks at each cve in the list of filtered cve objects and compares each affected configuration's manufacturer with a list of manufacturers that we are interested in.
#Quantifies manufactureres we care about with a 1 and ones we don't with a 0
#Saves each quantified manufacturer in a list with the cvss score in the format [CVSS3,CVSS2,1 or 0] : [5.5,6.5,0]
def qunatify_Mans(cves):
    ManList = [ "cisco",
                "palo alto",
                "dell"
    ]

    for cve in cves:
        ManRank=[]
        for device in cve.affects:
            ManRanks = []
            ManRanks.append(cve.cvss3)
            ManRanks.append(cve.cvss2)
            if device["manufacturer"] in ManList:
                ManRanks.append(1)
            else:
                ManRanks.append(0)
            ManRank.append(ManRanks)
        setattr(cve, "quantified", ManRank)
        

#Takes raw results from NVD and filters data we want into a list of CVE objects
#Calls recursive function for configurations and cpe cleaner for list of dictionaries
def generate_cve_list(rawcves):
    cves = []
    for rawcve in rawcves:
        cve = CVE()
        cpelist = []
        links = []
        setattr(cve, "cveID", rawcve["cve"]["CVE_data_meta"]["ID"])
        setattr(cve, "description", rawcve["cve"]["description"]["description_data"][0]["value"])
        cpes= get_children(rawcve["configurations"]["nodes"], cpelist)
        affects = clean_cpes(cpes)
        setattr(cve, "affects", affects)
        for data in rawcve["cve"]["references"]["reference_data"]:
            links.append(data["url"])
        setattr(cve, "links", links)
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