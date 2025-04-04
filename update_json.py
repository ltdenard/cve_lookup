#!/usr/bin/env python3
import os
import io
import json
import time
import zipfile
import argparse
import datetime
from pathlib import Path
try:
    import requests
except:
    print(f"requests module isn't installed. It is needed for updates.")

class CVELookup:
    def __init__(self, reinitialize=False, base_dir=None):
        self.BASE_DIR = os.getcwd()
        if base_dir:
            self.BASE_DIR = base_dir
        self.JSON_DL_FOLDER = os.path.join(self.BASE_DIR, "json_downloads")
        self.CVE_JSON_FILE = os.path.join(self.BASE_DIR, "all_cves.json")
        self.LAST_UPDATE_FILE = os.path.join(self.BASE_DIR, "last_update.txt")
        self.LAST_UPDATE_TIME = ""
        self.CVE_JSON = {}
        self.REINITIALZE = reinitialize
        # checks if the download folder exists
        if not os.path.exists(self.JSON_DL_FOLDER):
            os.makedirs(self.JSON_DL_FOLDER)
    
    def download_cve_jsons(self):
        base_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.zip"
        for year in range(2002,datetime.datetime.now(datetime.timezone.utc).year+1):
            print(f"Downloading: {base_url.format(year)}")
            response = requests.get(base_url.format(year), timeout=30)
            if response.ok:
                with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
                    zip_ref.extractall(self.JSON_DL_FOLDER)
            else:
                raise Exception(f"Zip download for {year} failed to download.")
            time.sleep(1)

    def download_recent_json(self):
        recent_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip"
        print(f"Downloading: {recent_url}")
        response = requests.get(recent_url, timeout=30)
        if response.ok:
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
                zip_ref.extractall(self.BASE_DIR)
        else:
            raise Exception(f"Zip download for {recent_url} failed to download.")
        return os.path.join(self.BASE_DIR, "nvdcve-1.1-recent.json")

    def download_modified_json(self):
        modified_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip"
        print(f"Downloading: {modified_url}")
        response = requests.get(modified_url, timeout=30)
        if response.ok:
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
                zip_ref.extractall(self.BASE_DIR)
        else:
            raise Exception(f"Zip download for {modified_url} failed to download.")
        return os.path.join(self.BASE_DIR, "nvdcve-1.1-modified.json")

    def download_vendor_xml(self):
        vendor_statements_url = "https://nvd.nist.gov/feeds/xml/cve/misc/vendorstatements.xml.zip"
        print(f"Downloading: {vendor_statements_url}")
        response = requests.get(vendor_statements_url, timeout=30)
        if response.ok:
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
                zip_ref.extractall(self.BASE_DIR)
        else:
            raise Exception(f"Zip download for {vendor_statements_url} failed to download.")
        return os.path.join(self.BASE_DIR, "vendorstatements.xml")

    def parse_and_update_cve_dict(self, cve_jsons_list):
        for cve_json_filename in cve_jsons_list:
            full_cve_json_filename = os.path.join(self.JSON_DL_FOLDER,cve_json_filename)
            print(f"Parsing {cve_json_filename}")
            with open(full_cve_json_filename, "r", encoding='utf-8') as f:
                data = json.load(f)
                for item in data.get('CVE_Items'):
                    cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                    desc = item.get('cve', {}).get('description', {}).get('description_data',[{}])[0].get('value')
                    pub = item.get('publishedDate')
                    mod = item.get('lastModifiedDate')
                    metrics = item.get('impact', {}).get('baseMetricV3', {})
                    cvss = metrics.get('cvssV3', {})
                    score = cvss.get('baseScore')
                    vector = cvss.get('vectorString')
                    if cve_id in self.CVE_JSON.keys():
                        self.CVE_JSON[cve_id].update({
                            "description": desc,
                            "publish_date": pub,
                            "last_modified_date": mod,
                            "base_score": score,
                            "vector": vector,
                        })
                    else:
                        self.CVE_JSON.update(
                            { 
                                cve_id:{
                                    "description": desc,
                                    "publish_date": pub,
                                    "last_modified_date": mod,
                                    "base_score": score,
                                    "vector": vector,
                                }
                            }
                        )
    # TODO: add in vendor statements

    def main_runner(self):
        utc_now = datetime.datetime.now(datetime.timezone.utc)
        hours_24_ago = utc_now - datetime.timedelta(hours=24)
        hours_48_ago = utc_now - datetime.timedelta(hours=48)
        if not os.path.exists(self.CVE_JSON_FILE) or self.REINITIALZE:
            self.download_cve_jsons()
        if not os.path.exists(self.LAST_UPDATE_FILE):
            # Automatically default to some old time if we've never updated
            self.LAST_UPDATE_TIME = hours_48_ago
        else:
            # open last update file and parse the time
            with open(self.LAST_UPDATE_FILE, "r") as f:
                self.LAST_UPDATE_TIME = datetime.datetime.fromisoformat(f.read().strip())
        if os.path.exists(self.CVE_JSON_FILE) and not self.REINITIALZE:
            with open(self.CVE_JSON_FILE, "r") as f:
                self.CVE_JSON = json.load(f)
        if ((self.LAST_UPDATE_TIME < hours_24_ago) and not os.path.exists(self.CVE_JSON_FILE)) or self.REINITIALZE:
            # create a unified json file
            base_cve_jsons_list = os.listdir(self.JSON_DL_FOLDER)
            self.parse_and_update_cve_dict(base_cve_jsons_list)
        # add in modified and recents
        if (self.LAST_UPDATE_TIME < hours_24_ago) or self.REINITIALZE:
            recent_json = self.download_recent_json()
            modified_json = self.download_modified_json()
            update_list = [recent_json, modified_json]
            self.parse_and_update_cve_dict(update_list)
        if (self.CVE_JSON and (self.LAST_UPDATE_TIME < hours_24_ago)) or self.REINITIALZE:
            print("Writing combined json file")
            with open(self.CVE_JSON_FILE, "w") as f:
                json.dump(self.CVE_JSON, f, indent=4, ensure_ascii=True, sort_keys=True)
            # Finally, update the timestamp of when we were last updated.
            print("Updating last run datetime")
            with open(self.LAST_UPDATE_FILE, "w", encoding="utf-8") as f:
                f.write(f"{utc_now.isoformat()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVE Lookup Update Tool")
    parser.add_argument(
        '--reinit',
        action='store_true',
        help='Reinitialize the CVE database (optional)'
    )
    parser.add_argument(
        '--base-dir',
        type=str,
        default='.',
        help='Base directory path for storing or reading CVE data (default: current directory)'
    )
    args = parser.parse_args()
    base_dir = Path(args.base_dir).resolve()
    obj = CVELookup(reinitialize=args.reinit, base_dir=base_dir)
    obj.main_runner()