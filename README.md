# 🔍 CVE Lookup Tool

**CVE Lookup Tool** is a Python-based command-line utility for downloading, caching, and searching through CVE (Common Vulnerabilities and Exposures) data from the [National Vulnerability Database (NVD)](https://nvd.nist.gov/).

This tool provides both **legacy** and **modern** methods for collecting CVE data, and includes a powerful local search interface to explore cached vulnerabilities without relying on external APIs at runtime.

---

## 🚀 Features

- 📥 **Download & Cache CVEs Locally**  
  Choose between the legacy NIST data feeds or the newer NVD REST API v2. An API key can be requested [here](https://nvd.nist.gov/developers/request-an-api-key).

- 🔍 **Search Cached CVEs by ID**  
  Use a local JSON file to quickly search for CVEs like `CVE-2024-3094`.

- 🛠️ **Fully Offline Capable**  
  Once cached, CVE data can be queried without an internet connection.

- ⚡ Fast performance, with options for full dataset or partial updates.

---

## 📦 Prerequisites

Make sure you have the following installed:

- ✅ Python 3.7 or higher
- ✅ Git
- ✅ Git Large File Storage
  ```
  brew install git-lfs
  git lfs install
  git lfs track <filename over 100mb>
  ```

---

## ⚙️ Installation

1. Clone the repo:
   ```
   git clone https://github.com/ltdenard/cve_lookup.git
   cd cve_lookup
   ```

2. Install required Python packages:
   ```
   python3 -mvenv env
   source env/bin/activate
   pip install -r requirements.txt
   ```

---

## 📡 Fetching CVE Data

You can fetch CVE data using **one of two methods**:

---

### 🧪 Method 1: `update_json.py` *(Legacy, Fast)*

- Uses the old NVD data feeds (2002–present)
- No API key required
- Faster and simpler
- **Will be deprecated by NVD soon**

```
python update_json.py
```

---

### 🔐 Method 2: `update_jsonv2.py` *(Recommended)*

- Uses the official NVD REST API v2
- Requires registering for a [free API key](https://nvd.nist.gov/developers/request-an-api-key)
- Complies with current and future standards

```
python update_jsonv2.py
```

*This runs `CVELookup.main_runner()` and saves the results to `all_cves.json` if the data isn't cached or is older than 24 hours.*

---

## 🔎 Searching for a CVE

Once you’ve downloaded the CVE data:

```
python search.py CVE-2024-3094
```

### Optional flags:

- `--file` Path to a custom CVE JSON file:
  ```
  python search.py CVE-2024-3094 --file ./my_cve_data.json
  ```

If the file is missing, it will automatically run `update_jsonv2.py` to populate it and if the data isn't cached or is older than 24 hours.

---

## 🛡 Example CVEs to Try

Here are some recent critical CVEs you can use to test:

- `CVE-2024-3094` – Backdoor in xz Utils
  ```
  python search.py CVE-2024-3094
  ```
- `CVE-2024-24919` – Check Point VPN unauth RCE
  ```
  python search.py CVE-2024-24919
  ```
- `CVE-2024-9680` – Firefox zero-day
  ```
  python search.py CVE-2024-9680
  ```

---

## 📝 License

MIT License