import os
import json
import argparse
from pathlib import Path
from update_jsonv2 import CVELookup

class CVESearcher:
    def __init__(self, json_path=None):
        self.json_path = os.path.join(os.getcwd(), "all_cves.json")
        if json_path:
            self.json_path = Path(json_path)
        self.data = self.load_data()

    def load_data(self):
        if not self.json_path.exists():
            CVELookup.main_runner(output_path=self.json_path)
        with open(self.json_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def search_cve(self, cve_id):
        return self.data.get(cve_id.upper())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search for a CVE in a local CVE JSON file.")
    parser.add_argument("cve_id", help="CVE ID to search (e.g., CVE-2023-12345)")
    parser.add_argument(
        "--file",
        default="all_cves.json",
        help="Path to the CVE JSON file (optional, default: all_cves.json)"
    )
    args = parser.parse_args()
    searcher = CVESearcher(json_path=args.file)
    result = searcher.search_cve(args.cve_id)
    if result:
        print(f"\nFound CVE: {args.cve_id}")
        print(json.dumps(result, indent=4))
    else:
        print(f"\nCVE not found: {args.cve_id}")
