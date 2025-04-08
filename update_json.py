import os
import re
import time
import json
import datetime
import argparse
from pathlib import Path
try:
    import requests
except:
    print(f"requests module isn't installed. It is needed for updates.")

class CVELookup:
    def __init__(self, api_key=None, output_folder=None, sleep_time=2, reinitialize=False, base_dir=None):
        self.api_key = os.getenv("NIST_API_KEY")
        if api_key:
            self.api_key = api_key
        self.BASE_DIR = os.getcwd()
        if base_dir:
            self.BASE_DIR = base_dir
        self.cve_output_folder = os.path.join(self.BASE_DIR, "cves_json")
        if output_folder:
            self.cve_output_folder = output_folder
        if not os.path.exists(self.cve_output_folder):
            os.makedirs(self.cve_output_folder)
        self.last_update_file = os.path.join(self.BASE_DIR, "last_update.txt")
        self.last_update_time = None
        self.sleep_time = sleep_time
        self.headers = {"apiKey": api_key} if api_key else {}
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.results_per_page = 2000
        self.date_chunk = 120  # NVD API limit: 120-day max range
        self.cve_json = {}
        self.reinitialize = reinitialize
        self.max_file_size = 90 * 1024 * 1024 # 90 MB

    def fetch_cves_in_range(self, start_date, end_date, start_index=0, accumulated=None, modified_date_search=False):
        if accumulated is None:
            accumulated = []
        if modified_date_search:
            params = {
                "lastModStartDate": start_date.isoformat(),
                "lastModEndDate": end_date.isoformat(),
                "startIndex": start_index,
                "resultsPerPage": self.results_per_page
            }
        else:
            params = {
                "pubStartDate": start_date.isoformat(),
                "pubEndDate": end_date.isoformat(),
                "startIndex": start_index,
                "resultsPerPage": self.results_per_page
            }
        print(f"Fetching {start_date.date()} to {end_date.date()} | startIndex={start_index}")
        response = requests.get(self.base_url, headers=self.headers, params=params)
        response_ok = False
        if not response.ok:
            response_ok = True
        while response_ok:
            print(f"Got Response Code: {response.status_code}... Waiting...")
            time.sleep(10)
            response = requests.get(self.base_url, headers=self.headers, params=params)
            if response.ok:
                response_ok = False
        response.raise_for_status()
        # NOTE: usings re to remove trailing commas since NIST doesn't follow
        # the RFC for json.
        # data = response.json()
        cleaned_text = re.sub(r',(\s*[}\]])', r'\1', response.text)
        data = json.loads(cleaned_text)
        results = data.get("vulnerabilities", [])
        accumulated.extend(results)
        total_results = data.get("totalResults", 0)
        print(f"Total in range: {total_results} | Collected: {len(accumulated)}")
        if start_index + self.results_per_page >= total_results:
            return accumulated
        time.sleep(self.sleep_time)
        return self.fetch_cves_in_range(start_date, end_date, start_index + self.results_per_page, accumulated, modified_date_search=modified_date_search)

    def fetch_all(self, current=None, end=None, all_data=None, modified_dates=False):
        if all_data is None:
            all_data = []
        if current is None:
            current = datetime.datetime(1999, 1, 1, tzinfo=datetime.timezone.utc)
        if end is None:
            end = datetime.datetime.now(datetime.timezone.utc)
        if current >= end:
            return all_data
        next_chunk = min(current + datetime.timedelta(days=self.date_chunk), end)
        chunk_data = self.fetch_cves_in_range(current, next_chunk, modified_date_search=modified_dates)
        all_data.extend(chunk_data)
        time.sleep(self.sleep_time)  # throttle between date chunks
        return self.fetch_all(next_chunk, end, all_data, modified_dates=modified_dates)

    def parse_and_update_cve_dict(self, cve_jsons_list):
        for item in cve_jsons_list:
            cve_data = item.get('cve', {})
            cve_id = cve_data.get('id')
            desc = cve_data.get('descriptions',[{}])[0].get('value')
            pub = cve_data.get('published')
            mod = cve_data.get('lastModified')
            metrics = cve_data.get('metrics', {})
            base_score = None
            vector_string = None
            score_version = None
            if metrics:
                for _, metric_list in metrics.items():
                    for metric_dict in metric_list:
                        cvss_data = metric_dict.get('cvssData')
                        if cvss_data:
                            base_score = cvss_data.get("baseScore")
                            score_version = cvss_data.get("version")
                            vector_string = cvss_data.get("vectorString")
                            if base_score and score_version and vector_string:
                                break
            if cve_id in self.cve_json.keys():
                self.cve_json[cve_id].update({
                    "description": desc,
                    "publish_date": pub,
                    "last_modified_date": mod,
                    "base_score": base_score,
                    "vector": vector_string,
                    "cvss_version": score_version
                })
            else:
                self.cve_json.update(
                    { 
                        cve_id:{
                            "description": desc,
                            "publish_date": pub,
                            "last_modified_date": mod,
                            "base_score": base_score,
                            "vector": vector_string,
                            "cvss_version": score_version
                        }
                    }
                )
    
    def read_chunks(self):
        combined_dict = {}
        chunk_files = sorted(
            [f for f in os.listdir(self.cve_output_folder) if f.endswith(".json")]
        )
        for chunk_file in chunk_files:
            file_path = os.path.join(self.cve_output_folder, chunk_file)
            with open(file_path, "r") as f:
                chunk = json.load(f)
                combined_dict.update(chunk)
                print(f"Loaded {chunk_file} ({len(chunk)} items)")
        return combined_dict

    def write_chunks(self, data):
        chunk = {}
        chunk_size = 0
        file_index = 1
        for key, value in data.items():
            temp_chunk = {key: value}
            temp_json = json.dumps(temp_chunk).encode('utf-8')
            temp_size = len(temp_json)
            if chunk_size + temp_size > self.max_file_size and chunk:
                # Write the current chunk to file
                file_path = os.path.join(self.cve_output_folder, f"{file_index}.json")
                with open(file_path, "w") as f:
                    json.dump(chunk, f)
                print(f"Written {file_path} ({chunk_size / (1024 * 1024):.2f} MB)")
                file_index += 1
                chunk = {}
                chunk_size = 0
            # Add to current chunk
            chunk[key] = value
            chunk_size += temp_size

        # Write remaining chunk
        if chunk:
            file_path = os.path.join(self.cve_output_folder, f"{file_index}.json")
            with open(file_path, "w") as f:
                json.dump(chunk, f)
            print(f"Written {file_path} ({chunk_size / (1024 * 1024):.2f} MB)")

    def main_runner(self):
        utc_now = datetime.datetime.now(datetime.timezone.utc)
        hours_24_ago = utc_now - datetime.timedelta(hours=24)
        hours_48_ago = utc_now - datetime.timedelta(hours=48)
        if not os.path.exists(self.cve_output_folder) or self.reinitialize:
            cve_data_list = self.fetch_all()
            self.parse_and_update_cve_dict(cve_data_list)
        if not os.path.exists(self.last_update_file):
            # Automatically default to some old time if we've never updated
            self.last_update_time = hours_48_ago
        else:
            # open last update file and parse the time
            with open(self.last_update_file, "r") as f:
                self.last_update_time = datetime.datetime.fromisoformat(f.read().strip())
        if os.path.exists(self.cve_output_folder) and not self.reinitialize:
            self.cve_json = self.read_chunks()
        # refresh the data with recent published and modified since the last run
        if (self.last_update_time < hours_24_ago) or self.reinitialize:
            print("Fetching recently published CVEs...")
            recent_cves_list = self.fetch_cves_in_range(self.last_update_time, utc_now, modified_date_search=False)
            print("Fetching recently modified CVEs...")
            modified_cves_list = self.fetch_cves_in_range(self.last_update_time, utc_now, modified_date_search=True)
            update_list = recent_cves_list + modified_cves_list
            print("Parsing updates...")
            self.parse_and_update_cve_dict(update_list)
        if (self.cve_json and (self.last_update_time < hours_24_ago)) or self.reinitialize:
            self.write_chunks(self.cve_json)
            # Finally, update the timestamp of when we were last updated.
            print("Updating last run datetime")
            with open(self.last_update_file, "w", encoding="utf-8") as f:
                f.write(f"{utc_now.isoformat()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download all CVEs using the NVD API (v2).")
    parser.add_argument("--output", default="cves_json", help="Output folder (default: all_cves).")
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
    obj = CVELookup(output_folder=args.output, reinitialize=args.reinit, base_dir=base_dir)
    obj.main_runner()