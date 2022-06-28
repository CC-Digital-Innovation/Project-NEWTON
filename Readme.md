# Email-API
## Summary
This project pulls Common Vulnerabilities and exposures from the [National Vulnerability database](https://nvd.nist.gov/vuln/search) that were modified in the 12 hour window prior to code execution. It then uses a decision tree algorithm to classify CVEs as critial to our systems or not. Once they have been classified, action steps are taken to search our CMDB, compile a list of potentially affected devices, email that list, and save results to a db for eventual automated upkeep. 

## Features
* CVE retreival using python requests and the NVD API
* sklearn module to create and utilize decision tree 
* leverages email API running in a container
* Saves results to NoCoDB database

## Requirements
```bash
pip install -r requirements.txt
```
The following will be installed:
* [FastAPI](https://github.com/tiangolo/fastapi) API module for CMDB search function

* [pandas](https://github.com/pandas-dev/pandas) Data formatting

* [uvicorn](https://github.com/encode/uvicorn) runs FastAPI 

* [Loguru](https://github.com/Delgan/loguru) logging

* matplotlib: plotting tool for sklearn ML visualization
* scikit-learn: Python machine learning module
* pydotplus: Another tool used for plotting/vizualization
* requests: python requests module

## Parameters
CMDB Searching API takes:
Numeric Model number
Vendor
or
list of numeric model numbers
list of coorisponding vendors
## Usage

config requires tokens, urls, and some email information. All outlined in the example file provided
run main.py to start up cmdb searching api
run newton.py to search nvd, classify results, hand them to api, and take current actions


## Compatability
Python 3.6+


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## Credits
Ben Verley <<benjamin.verly@computacenter.com>>

## License
[MIT](https://choosealicense.com/licenses/mit/)
