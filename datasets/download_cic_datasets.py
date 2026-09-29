#!/usr/bin/env python3
"""Download CIC datasets that require form registration."""
import requests
import os
import sys
import urllib3

# Suppress SSL warnings for the PQC IP-based URL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'identity',
    'Connection': 'keep-alive',
}

FORM_DATA = {
    'first_name': 'Research',
    'last_name': 'User',
    'email': 'test@test.com',
    'institution': 'Research Org',
    'job_title': 'Researcher',
    'country': 'United States'
}

def register(base_url, verify_ssl=True):
    """Submit registration form and return a requests session with cookies."""
    session = requests.Session()
    session.headers.update(HEADERS)
    resp = session.post(f"{base_url}/insert.php", data=FORM_DATA, timeout=20, verify=verify_ssl)
    result = resp.json()
    if result.get('ok'):
        token = session.cookies.get('Token') or 'N/A'
        print(f"  [OK] Registered. Token={token[:12]}...")
        return session
    else:
        print(f"  [FAIL] Registration failed: {result}")
        return None

def download_file(session, base_url, encoded_filepath, local_filename, output_dir, verify_ssl=True):
    """Download a single file from the CIC dataset."""
    os.makedirs(output_dir, exist_ok=True)
    outpath = os.path.join(output_dir, local_filename)

    # Skip if already downloaded
    if os.path.exists(outpath) and os.path.getsize(outpath) > 0:
        size = os.path.getsize(outpath)
        print(f"  [SKIP] {local_filename} already exists ({size} bytes)")
        return True

    url = f"{base_url}/download.php?file={encoded_filepath}"
    print(f"  [DL]   {local_filename} ...", end='', flush=True)

    try:
        dl = session.get(url, timeout=30, stream=True, verify=verify_ssl)
        if dl.status_code != 200:
            print(f"FAIL (HTTP {dl.status_code})")
            return False

        total = 0
        with open(outpath, 'wb') as f:
            for chunk in dl.iter_content(chunk_size=65536):
                if chunk:
                    f.write(chunk)
                    total += len(chunk)

        if total == 0:
            print(f"FAIL (0 bytes received)")
            os.remove(outpath)
            return False

        print(f"OK ({total} bytes)")
        return True
    except Exception as e:
        print(f"FAIL ({e})")
        if os.path.exists(outpath) and os.path.getsize(outpath) == 0:
            os.remove(outpath)
        return False


# ============================================================
# 1. TOR DATASET (ISCX-Tor-NonTor-2017)
# ============================================================
print("\n=== TOR DATASET (ISCX-Tor-NonTor-2016) ===")
TOR_BASE = "https://cicresearch.ca/CICDataset/ISCX-Tor-NonTor-2017"
TOR_DIR = "/home/rick/SES-v1/datasets/tor_nonTor_2016"

session = register(TOR_BASE)
if session:
    # CSVs (small)
    download_file(session, TOR_BASE, "CSVs%2FScenario-A-merged_5s.csv",
                  "Scenario-A-merged_5s.csv", f"{TOR_DIR}/CSVs")
    download_file(session, TOR_BASE, "CSVs%2FScenario-B-merged_5s.csv",
                  "Scenario-B-merged_5s.csv", f"{TOR_DIR}/CSVs")
    # PCAPs (large - may take a while)
    download_file(session, TOR_BASE, "PCAPs%2FNonTor.tar.xz",
                  "NonTor.tar.xz", f"{TOR_DIR}/PCAPs")
    download_file(session, TOR_BASE, "PCAPs%2FTor.zip",
                  "Tor.zip", f"{TOR_DIR}/PCAPs")


# ============================================================
# 2. CIC-IDS-2017 DATASET
# ============================================================
print("\n=== CIC-IDS-2017 DATASET ===")
IDS_BASE = "https://cicresearch.ca/CICDataset/CIC-IDS-2017"
IDS_DIR = "/home/rick/SES-v1/datasets/cic_ids_2017"

session = register(IDS_BASE)
if session:
    # CSV files
    download_file(session, IDS_BASE, "CIC-IDS-2017%2FCSVs%2FGeneratedLabelledFlows.zip",
                  "GeneratedLabelledFlows.zip", f"{IDS_DIR}/CSVs")
    download_file(session, IDS_BASE, "CIC-IDS-2017%2FCSVs%2FGeneratedLabelledFlows.md5",
                  "GeneratedLabelledFlows.md5", f"{IDS_DIR}/CSVs")
    download_file(session, IDS_BASE, "CIC-IDS-2017%2FCSVs%2FMachineLearningCSV.zip",
                  "MachineLearningCSV.zip", f"{IDS_DIR}/CSVs")
    download_file(session, IDS_BASE, "CIC-IDS-2017%2FCSVs%2FMachineLearningCSV.md5",
                  "MachineLearningCSV.md5", f"{IDS_DIR}/CSVs")
    # PCAP files
    for day in ["Monday-WorkingHours", "Tuesday-WorkingHours", "Wednesday-workingHours",
                "Thursday-WorkingHours", "Friday-WorkingHours"]:
        download_file(session, IDS_BASE, f"CIC-IDS-2017%2FPCAPs%2F{day}.pcap",
                      f"{day}.pcap", f"{IDS_DIR}/PCAPs")
        download_file(session, IDS_BASE, f"CIC-IDS-2017%2FPCAPs%2F{day}.md5",
                      f"{day}.md5", f"{IDS_DIR}/PCAPs")


# ============================================================
# 3. CIC-PQC-OAV-2025 DATASET (IP-based HTTPS)
# ============================================================
print("\n=== CIC-PQC-OAV-2025 DATASET ===")
PQC_BASE = "https://205.174.165.80/CICDataset/CIC-PQC_OAV%20v1"
PQC_DIR = "/home/rick/SES-v1/datasets/cic_pqc_oav_2025"

session = register(PQC_BASE, verify_ssl=False)
if session:
    # Get browse page to find available files
    try:
        browse = session.get(f"{PQC_BASE}/browse.php", timeout=15, verify=False)
        print(f"  Browse page ({len(browse.text)} chars):")
        # Extract folder/file links
        import re
        links = re.findall(r'href="([^"]+)"', browse.text)
        download_links = [l for l in links if 'download.php' in l]
        folder_links = re.findall(r'browse\.php\?p=([^"&]+)', browse.text)
        print(f"  Folders: {folder_links}")
        print(f"  Download links: {download_links}")

        if not download_links and folder_links:
            # Navigate into subfolders
            for folder in folder_links:
                sub_browse = session.get(f"{PQC_BASE}/browse.php?p={folder}", timeout=15, verify=False)
                sub_downloads = re.findall(r'download\.php\?file=([^"&]+)', sub_browse.text)
                sub_filenames = re.findall(r'>([^<]+\.\w+)</a>', sub_browse.text)
                print(f"  Subfolder '{folder}' downloads: {sub_downloads}")
                for i, dl_path in enumerate(sub_downloads):
                    # Extract filename from URL-encoded path
                    fname = dl_path.split('%2F')[-1]
                    download_file(session, PQC_BASE, dl_path, fname, PQC_DIR, verify_ssl=False)
    except Exception as e:
        print(f"  Browse error: {e}")

print("\n=== DONE ===")
