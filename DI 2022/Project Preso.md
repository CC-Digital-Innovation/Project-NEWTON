---
marp: true
---

# Project N.E.W.T.O.N.
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
![bg left](https://raw.githubusercontent.com/pwagoner/Wayne-Newton/main/Wayne%20Newtons%20(1).png)
- **Ben Verley** - Lead Developer
- **Paige Wagoner** - Team PM
- **VB Mehta** - Technical Resource
- **Chris Vik** - Technical Resource
- **Stefan Axelson** - Technical Resource
- **Chris Villasenor** - Technical Resource
- **Mike Wojke** - Team Old Guy

---
<style scoped>
    h1 {
        text-align: center
    }
    img {
        display: block;
 margin-left: auto;
 margin-right: auto;
    }
</style>
# Execution
![width:2000 height:500](https://raw.githubusercontent.com/Bverley92/DI-2022-Personal-Preso/main/Photos/SDLC.jpeg)

---
## Analysis/Planning
- Create slack channel "2022-di-team-wayne-newton"
- Create project dashboard (https://app.smartsheet.com/dashboards/pRF3FgcfM8Wp7RQc2FXQP23Q493qGW66P3G3Fm31)
- Schedule weekly meetings (2x a week - Tues, Thurs)
- Identify topic for project
- Gather requirements and identify risks
- Confirm capability to complete project
- Assign roles and investigation of each role
- Define workflow for code to follow

---
## Defining
- Discovery at existing customer environments to confirm inventory, vendor, and hardware model #
- True up SNOW CMDB for chosen customers
- Define alerting, common threats, monitoring parameters and user interface
- Identify SNOW integration/data retrieval methods
- Research solutions to classify CVEs, how CVEs store model #, and how to implement decision tree

---
## Designing
- Retrieve CVEs from database
- Classify CVEs into critical to our systems or not
- Grab hardware vendor model #'s from the CVE and search our CMDB for potentially effected devices
- Compile a list of devices, customers, etc and send out this list via email
## *Future Phase Enhancements*
- *Auto check vendor support sites for availability of security patches related to the discovered CVE*
- *Auto check/update for new device models in CMDB for project N.E.W.T.O.N. to check on CVE's for*
- *Create a matrix of vulnerable devices to XS engineers to work from to confirm when patches are applied and secure*

---
<style scoped>
    h2 {
        text-align: center
    }
    img {
        display: block;
 margin-left: auto;
 margin-right: auto;
    }
</style>
## Building & Testing

<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
<script>mermaid.initialize({startOnLoad:true});
</script>

<div class = "mermaid">
flowchart TD
    A[CVE Classifier Code] -->B{CMDB Search}
    A[CVE Classifier Code] -->C{Vulnerabilities}
    A[CVE Classifier Code] -->D{Workflow}
    C -->e[Research CVE Pieces]
    C -->ee[Make A Decision Tree]
    B -->f[Generate Affected List]
    B -->ff[Ensure Searchability]
    B -->fff[Search CMDB]
    D -->g[Get CVEs]
    g -->h(Classify CVEs)
    h -->i(Actionable)
    h -->ii(Not Actionable)
    ii -->j[Ignore]
    i -->jj[Search Cmdb]
    jj -->k[Email/Alert]
    jj -->kk[Track hits in DB]
    e -->l[Best Way to search for CVE]
    e -->ll[Filter CVE data]
    e -->lll[Generate Test/Training Set]
    e -->llll[Learn about CPE strings]
    ee -->m[Learn how to use pymodules]
    m -->n[Sklearn]
    m -->nn[NumPy]
    m -->nnn[Pandas]
</div>

---
![bg contain](https://raw.githubusercontent.com/pwagoner/Wayne-Newton/main/mvp.png)

---
## Deployment
- Initial deployment through local resources (laptop)
- Test plan/MVP iterations
- Planned product release in container to be available at all times for ad hoc searches

---
## How we reached MVP/POC
- **Established initial requirements of hardware vendor and model #**
- **CVE configs have 3 configuration formats (simple, versioned, complex)**
    - Simple: just CPE string
    - Versioned: CPE string and version start/end
    - Complex: CPE string and complimentary parts that have additional CPE strings
- **Model # CMDB search**
    - Right now, only searching for numeric model # and manufacturer
    - Larger data structure must be hashed out

---
## Challenges & Solutions
- **CMDB matching**
    - Search CMDB with manufacturer name and pure # of model # yields results
- **Getting CPE strings in the json formatted CVE**
    - Recursive function to iterate over children
- **Figuring out a way to quantify "impact to us"**
    - Code looks at manufacture and compares against a list
    - If manufacturer is Cisco, that is given value 1. If other, value 0
- **CVE configuration complexity**
    - Grab all CPE strings as that is the simplest format to work with
    - Expand configs once that's established

---
![bg](https://raw.githubusercontent.com/pwagoner/Wayne-Newton/main/product-demo-themes.jpg)

---
<style scoped>
    h2 {
        text-align: center
    }
    img {
        display: block;
 margin-left: auto;
 margin-right: auto;
    }
</style>
## Decision Tree
![width:650 height:600](https://raw.githubusercontent.com/pwagoner/Wayne-Newton/main/decision%20tree.png)

---
# What did we learn about ourselves and each other
- Ben is a badass coder!
- Team projects > Personal projects
- Vik is a closet Wayne Newton fan
- Marp and Markdown isn't as bad as it seems

---
# Anything we would have done differently? How we think it would have impacted outcome
- Could have applied different machine learning algorithms
- Neural Network instead of Decision Tree

---
# Thank You Very Much! Questions?
