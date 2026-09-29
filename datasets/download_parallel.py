#!/usr/bin/env python3
"""Download CIC datasets with parallel downloads for small files."""
import requests
import os
import re
import sys
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

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


def make_session(base_url, verify_ssl=True):
    """Register and return a session with cookies."""
    session = requests.Session()
    session.headers.update(HEADERS)
    resp = session.post(f"{base_url}/insert.php", data=FORM_DATA, timeout=20, verify=verify_ssl)
    result = resp.json()
    if result.get('ok'):
        return session
    return None


def download_file(session, base_url, encoded_filepath, local_name, out_dir, verify_ssl=True):
    """Download a single file using streaming to handle large files."""
    os.makedirs(out_dir, exist_ok=True)
    outpath = os.path.join(out_dir, local_name)

    if os.path.exists(outpath) and os.path.getsize(outpath) > 0:
        return f"[SKIP] {local_name}: {os.path.getsize(outpath)} bytes (exists)"

    url = f"{base_url}/download.php?file={encoded_filepath}"
    try:
        dl = session.get(url, timeout=60, stream=True, verify=verify_ssl)
        if dl.status_code != 200:
            return f"[FAIL] {local_name}: HTTP {dl.status_code}"
        total = 0
        with open(outpath, 'wb') as f:
            for chunk in dl.iter_content(chunk_size=1048576):
                if chunk:
                    f.write(chunk)
                    total += len(chunk)
        size = os.path.getsize(outpath)
        return f"[OK]   {local_name}: {size} bytes"
    except Exception as e:
        if os.path.exists(outpath) and os.path.getsize(outpath) == 0:
            os.remove(outpath)
        return f"[FAIL] {local_name}: {e}"


# ============================================================
# TOR DATASET
# ============================================================
print("=== TOR DATASET ===", flush=True)
TOR_BASE = "https://cicresearch.ca/CICDataset/ISCX-Tor-NonTor-2017"
TOR_DIR = "/home/rick/SES-v1/datasets/tor_nonTor_2016"
tor_session = make_session(TOR_BASE)

if tor_session:
    tor_files = [
        ("Scenario-A-merged_5s.csv", "CSVs%2FScenario-A-merged_5s.csv", f"{TOR_DIR}/CSVs"),
        ("Scenario-B-merged_5s.csv", "CSVs%2FScenario-B-merged_5s.csv", f"{TOR_DIR}/CSVs"),
    ]
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(download_file, tor_session, TOR_BASE, fp, ln, od)
                   for ln, fp, od in tor_files]
        for f in as_completed(futures):
            print(f"  {f.result()}", flush=True)

    # Download PCAPs as well (they may be large)
    torrent_pcap = [
        ("NonTor.tar.xz", "PCAPs%2FNonTor.tar.xz", f"{TOR_DIR}/PCAPs"),
        ("Tor.zip", "PCAPs%2FTor.zip", f"{TOR_DIR}/PCAPs"),
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(download_file, tor_session, TOR_BASE, fp, ln, od)
                   for ln, fp, od in torrent_pcap]
        for f in as_completed(futures):
            print(f"  {f.result()}", flush=True)
else:
    print("  [FAIL] Could not register for Tor dataset", flush=True)


# ============================================================
# CIC-IDS-2017 DATASET
# ============================================================
print("\n=== CIC-IDS-2017 DATASET ===", flush=True)
IDS_BASE = "https://cicresearch.ca/CICDataset/CIC-IDS-2017"
IDS_DIR = "/home/rick/SES-v1/datasets/cic_ids_2017"
ids_session = make_session(IDS_BASE)

if ids_session:
    # CSV files (smaller, download in parallel)
    ids_csv_files = [
        ("GeneratedLabelledFlows.zip", "CIC-IDS-2017%2FCSVs%2FGeneratedLabelledFlows.zip", f"{IDS_DIR}/CSVs"),
        ("GeneratedLabelledFlows.md5", "CIC-IDS-2017%2FCSVs%2FGeneratedLabelledFlows.md5", f"{IDS_DIR}/CSVs"),
        ("MachineLearningCSV.zip", "CIC-IDS-2017%2FCSVs%2FMachineLearningCSV.zip", f"{IDS_DIR}/CSVs"),
        ("MachineLearningCSV.md5", "CIC-IDS-2017%2FCSVs%2FMachineLearningCSV.md5", f"{IDS_DIR}/CSVs"),
    ]
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(download_file, ids_session, IDS_BASE, fp, ln, od)
                   for ln, fp, od in ids_csv_files]
        for f in as_completed(futures):
            print(f"  {f.result()}", flush=True)

    # PCAP files (large - 7-13GB each)
    days = ["Monday-WorkingHours", "Tuesday-WorkingHours", "Wednesday-workingHours",
            "Thursday-WorkingHours", "Friday-WorkingHours"]
    ids_pcap_files = []
    for day in days:
        ids_pcap_files.append((f"{day}.pcap", f"CIC-IDS-2017%2FPCAPs%2F{day}.pcap", f"{IDS_DIR}/PCAPs"))
        ids_pcap_files.append((f"{day}.md5", f"CIC-IDS-2017%2FPCAPs%2F{day}.md5", f"{IDS_DIR}/PCAPs"))
    
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(download_file, ids_session, IDS_BASE, fp, ln, od)
                   for ln, fp, od in ids_pcap_files]
        for f in as_completed(futures):
            print(f"  {f.result()}", flush=True)
else:
    print("  [FAIL] Could not register for IDS-2017 dataset", flush=True)


# ============================================================
# CIC-PQC-OAV-2025 DATASET
# ============================================================
print("\n=== CIC-PQC-OAV-2025 DATASET ===", flush=True)
PQC_BASE = "https://205.174.165.80/CICDataset/CIC-PQC_OAV%20v1"
PQC_DIR = "/home/rick/SES-v1/datasets/cic_pqc_oav_2025"
pqc_session = make_session(PQC_BASE, verify_ssl=False)

if pqc_session:
    # Browse the root to find folders
    try:
        browse = pqc_session.get(f"{PQC_BASE}/browse.php", timeout=15, verify=False)
        folders = re.findall(r'browse\.php\?p=([^"&]+)', browse.text)
        print(f"  Folders found: {folders}", flush=True)
        
        all_pqc_files = []
        for folder in folders:
            sub_browse = pqc_session.get(f"{PQC_BASE}/browse.php?p={folder}", timeout=15, verify=False)
            # Extract download links and filenames
            dl_paths = re.findall(r'download\.php\?file=([^"&]+)', sub_browse.text)
            # Also try to get filenames from the text
            filenames = re.findall(r'>([^<>]*\.\w+)</a>', sub_browse.text)
            for i, dl_path in enumerate(dl_paths):
                fname = filenames[i] if i < len(filenames) else dl_path.split('%2F')[-1]
                all_pqc_files.append((fname, dl_path))
        
        # Also check root for direct downloads
        root_dl_paths = re.findall(r'download\.php\?file=([^"&]+)', browse.text)
        root_filenames = re.findall(r'>([^<>]*\.\w+)</a>', browse.text)
        for i, dl_path in enumerate(root_dl_paths):
            fname = root_filenames[i] if i < len(root_filenames) else dl_path.split('%2F')[-1]
            all_pqc_files.append((fname, dl_path))
        
        print(f"  PQC files to download: {len(all_pqc_files)}", flush=True)
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(download_file, pqc_session, PQC_BASE, dl_path, fname, PQC_DIR, False)
                       for fname, dl_path in all_pqc_files]
            for f in as_completed(futures):
                print(f"  {f.result()}", flush=True)
    except Exception as e:
        print(f"  [ERROR] {e}", flush=True)
else:
    print("  [FAIL] Could not register for PQC dataset", flush=True)


print("\n=== ALL CIC DOWNLOADS COMPLETE ===", flush=True)
