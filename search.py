import os
import json
import argparse
from pathlib import Path
from update_json import CVELookup

class CVESearcher:
    def __init__(self, json_folder_path=None):
        self.json_path = Path(os.path.join(os.getcwd(), "cves_json"))
        if json_folder_path:
            self.json_path = Path(json_folder_path)
        self.cvelookup_obj = CVELookup(output_folder=self.json_path)

    def load_data(self):
        if not self.json_path.exists():
            self.cvelookup_obj.main_runner(output_path=self.json_path)
        self.json_data = self.cvelookup_obj.read_chunks()
        return self.json_data

    def search_cve(self, cve_id):
        data = self.load_data()
        return data.get(cve_id.upper())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search for a CVE in a local CVE JSON file.")
    parser.add_argument("cve_id", help="CVE ID to search (e.g., CVE-2023-12345)")
    parser.add_argument(
        "--folder",
        default="cves_json",
        help="Path to the CVE JSON folder (optional, default: cves_json)"
    )
    args = parser.parse_args()
    searcher = CVESearcher(json_folder_path=args.folder)
    result = searcher.search_cve(args.cve_id)
    if result:
        print(f"\nFound CVE: {args.cve_id}")
        print(json.dumps(result, indent=4))
    else:
        print(f"\nCVE not found: {args.cve_id}")
