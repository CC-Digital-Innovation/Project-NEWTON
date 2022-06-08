---
marp: true
---

# Project N.E.W.T.O.N.
this is content
## Nefarious Event Warnings Targeting OS Noncompliance
### Team Wayne Newton
### Digital Innovation Project 2022
![bg left:33%](https://raw.githubusercontent.com/pwagoner/Wayne-Newton/main/newton.jpg)

---
# N.E.W.T.O.N. Abstract
### Project N.E.W.T.O.N. aims to reduce the notification delay for the DI XS team to become aware of possible discovered global vulnerabilities in devices managed by XS programs. It will also provide a list of devices in our SNOW CMDB that may be known to be affected by these vulnerabilities.
## Why?
- Reduce the risk of missing new vulnerability announcement
- Reduce the time for notification of potential threats
- Reduce time to value for our customers
- Increase XS stickiness in an account
- This function can be mentioned/listed in sales discussions as another valuable service delivered by DI XS

---
# Team Wayne Newton
ORG CHART (STEFAN)

---
# Execution

---
## Discovery
- Discovery at existing customer environments to confirm inventory, hardware model # and software version
- True up SNOW CMDB for chosen customers
- Standardize device software per model for all supported devices
- Define alerting, common threats, monitoring parameters and user interface
- Identify SNOW integration/data retrieval methods
- Research solutions to classify CVEs, how CVEs store model #, and how to implement decision tree

---
## Implementation
- Retrieve CVEs from database
- Classify CVEs into critical to our systems or not
- Grab model #'s/firmware versions from the CVE and search our CMDB for potentially effected devices
- Compile a list of devices, customers, etc and send out this list via email
## *Future Phase Enhancements*
- *Auto check vendor support sites for availability of security patches related to the discovered CVE*
- *Auto check of devices in our CMDB to check CVE db for*
- *Create a matrix of vulnerable devices to XS engineers to work from to confirm when patches are applied and secure*

---
![bg contain](https://raw.githubusercontent.com/pwagoner/Wayne-Newton/main/Execution.png)

---
# Outcome (MVP)

---
## "Shortcuts" Taken to Reach MVP/POC
- **CVE configs have 3 configuration formats (simple, versioned, complex)**
    * Simple: just CPE string
    * Versioned: CPE string and version start/end
    * Complex: CPE string and complimentary parts that have additional CPE strings
- **Only searching CMDB for model # and manufacturers that match CPE string**
    * Software and Firmware versions are not stored in CMDB
    * Not demo-able
- **Model # CMDB search**
    * Right now, only searching for numeric model # and manufacturer
    * Larger data structure must be hashed out

---
## Challenges & Solutions
- **Getting CPE strings in the json formatted CVE**
    * Recursive function to iterate over children
- **Figuring out a way to quantify "impact to us"**
    * Code looks at manufacture and compares against a list
    * If manufacturer is Cisco, that is given value 1. If other, value 0
- **CMDB matching**
    * Search CMDB with manufacturer name and pure # of model # yields results
- **CVE configuration complexity**
    * Grab all CPE strings as that is the simplest format to work with
    * Expand configs once that's established

---
# Demo

---
# Anything we would have done differently? How we think it would have impacted outcome