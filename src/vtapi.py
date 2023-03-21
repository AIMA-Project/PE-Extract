'''
@file vtapi.py
@author Drew Wheeler

@brief Contains a basic interface for obtaining VirusTotal reports.

Reports from VirusTotal for a given hash value can be obtained via the API. From this, various
information relating to pre-ran scans can be gathered.

Utilizing the VirusTotal API requires an API key tied to a registered account to work properly. By
default, the key should be placed in a "virustotal.key" file in the root of the project directory.
This value can be changed, however. See the following link for more information on how to get
started with the VirusTotal API: https://support.virustotal.com/hc/en-us/articles/115002100149-API

@see pe.py

'''


import requests


def vt_load_api_key (key_file: str) -> str:
    vt_api_key = ""
    with open (key_file, 'r') as key_read:
        vt_api_key = key_read.readline()
    return vt_api_key

def vt_hash_request (hash: str, vt_api_key: str) -> requests.models.Response:
    req_header = {"accept": "application/json",
                  "x-apikey": vt_api_key}
    vt_report = requests.get ("https://www.virustotal.com/api/v3/files/" + hash, headers = req_header)
    if vt_report.status_code == 200:
        return vt_report
    else:
        return None



if __name__ == "__main__":
    api_key = vt_load_api_key ("virustotal.key")
    vt_hash_request ("7a4df2fc82c0b553d0b703f51635fd62cf02553706f942c66d752c1d8fae207b", api_key)
