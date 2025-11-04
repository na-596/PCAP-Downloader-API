import requests
import csv
from io import BytesIO
import urllib.parse
from requests.auth import HTTPDigestAuth
import urllib3
import os
import time
from datetime import datetime
import threading
from merge import merge_pcaps
from typing import Optional
from athena_query import execute_athena_query
from config import ES_HOST_TEMPLATE, ES_USER, ES_PASS
import math

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def run_pcap_process(iccid, time_window_start, time_window_end, max_process_size, radius_wanted):
    # dotenv is loaded centrally in publish_gui.config
    # Print a short summary to the caller (GUI or CLI)
    print(
        f"ICCID: {iccid}, Time window: {time_window_start} to {time_window_end}",
        flush=True,
    )

    athena_time_start = time.time()
    athena_data = execute_athena_query(iccid, time_window_start, time_window_end)

    if athena_data is None:
        raise RuntimeError("No data returned from Athena query.")

    print(
        f"Athena query execution time: {time.time() - athena_time_start:.2f} seconds",
        flush=True,
    )

    pcap_url_list = []
    csv_url_list = []
    details_list = []

    for code, msisdn, imsi, ip, start_time, stop_time in athena_data:
        details_list.extend([msisdn, imsi, ip])

        if radius_wanted:
            expression = f"ip.src == {ip} || ip.dst == {ip} || radius.framed-ip == {ip} || radius.mac == {msisdn} || radius.user == {imsi}"
        else:
            expression = f"ip.src == {ip} || ip.dst == {ip}"

        start_dt = datetime.strptime(start_time, "%Y/%m/%d %H:%M:%S")
        stop_dt = datetime.strptime(stop_time, "%Y/%m/%d %H:%M:%S")
        start_time = int(datetime(start_dt.year, start_dt.month, start_dt.day, start_dt.hour, 0, 0).timestamp())
        stop_time = int(datetime(stop_dt.year, stop_dt.month, stop_dt.day, stop_dt.hour, 0, 0).timestamp())
        encoded_expr = urllib.parse.quote(expression)

    # ES_HOST_TEMPLATE should contain a '{code}' placeholder, e.g. "{code}ws01.example.net"
        base_url = f"https://{ES_HOST_TEMPLATE.format(code=code)}"
        query_params = f"expression={encoded_expr}&startTime={start_time}&stopTime={stop_time}&length=10000000"
        csv_url = f"{base_url}/sessions.csv?{query_params}"
        pcap_url = f"{base_url}/sessions.pcap?{query_params}"

        if pcap_url not in pcap_url_list:
            pcap_url_list.append(pcap_url)
        if csv_url not in csv_url_list:
            csv_url_list.append(csv_url)

    print(
        f"Elastic Search URLs: {[url.replace('.csv', '') for url in csv_url_list]}",
        flush=True,
    )
    print(f"Details list: {details_list}", flush=True)

    shared_data = {
        "total_bytes": 0,
        "size_limit_flag": False,
        "max_bytes": max_process_size,
    }

    def check_csv_data(csv_url):
        max_bytes = shared_data["max_bytes"]
        current_file_bytes = 0
        username = ES_USER
        password = ES_PASS
        print("Fetching session CSV...", flush=True)

        response = requests.get(
            csv_url, stream=True, verify=False, auth=HTTPDigestAuth(username, password)
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"Error fetching CSV: {response.status_code}\n{response.text[:500]}"
            )

        reader = csv.reader(response.iter_lines(decode_unicode=True))
        header = next(reader, None)
        if not header:
            raise RuntimeError("CSV missing header.")

        header_map = {name.strip().lower(): idx for idx, name in enumerate(header)}
        bytes_idx = header_map.get("bytes")
        databytes_idx = header_map.get("data bytes")
        if bytes_idx is None or databytes_idx is None:
            raise RuntimeError("Missing 'Bytes' or 'Data bytes' in CSV.")

        row_count = 0
        for row in reader:
            row_count += 1
            try:
                byte_val = int(row[bytes_idx]) + int(row[databytes_idx])
                shared_data["total_bytes"] += byte_val
                current_file_bytes += byte_val
            except Exception:
                continue
            if shared_data["total_bytes"] * 0.66 > max_bytes:
                shared_data["size_limit_flag"] = True

        if current_file_bytes == 0:
            pcap_url_list.remove(csv_url.replace("/sessions.csv?", "/sessions.pcap?"))
            print(f"CSV has no data, PCAP removed: {csv_url[8:11]}", flush=True)
        else:
            print(
                f"CSV processed: {row_count} rows, {current_file_bytes / (1024*1024):.2f} MB, {csv_url[8:11]}",
                flush=True,
            )

    csv_threads = []
    for csv_url in csv_url_list:
        thread = threading.Thread(target=check_csv_data, args=(csv_url,), daemon=True)
        csv_threads.append(thread)
        thread.start()
    for t in csv_threads:
        t.join()

    est = shared_data["total_bytes"] * 0.66
    print(
        f"Total CSV bytes estimate: {est / (1024*1024):.2f} MB",
        flush=True,
    )

    if shared_data["size_limit_flag"]:
        raise RuntimeError(
            f"Data exceeds size limit {shared_data['max_bytes']/1024/1024} MB. Exiting."
        )

    print("Downloading PCAP files...", flush=True)
    pcap_create_time_start = time.time()
    username = ES_USER
    password = ES_PASS
    pcap_fileobjs: list[Optional[BytesIO]] = [None] * len(pcap_url_list)

    def download_pcap(pcap_url, idx):
        # Download a PCAP into an in-memory BytesIO so merge logic can read it
        resp = requests.get(
            pcap_url, verify=False, auth=HTTPDigestAuth(username, password), timeout=900
        )
        if resp.status_code == 200:
            pcap_fileobjs[idx] = BytesIO(resp.content)
        else:
            print(f"Failed to download {pcap_url}", flush=True)

    download_threads = []
    for idx, url in enumerate(pcap_url_list):
        thread = threading.Thread(target=download_pcap, args=(url, idx), daemon=True)
        download_threads.append(thread)
        thread.start()
    for t in download_threads:
        t.join()

    pcap_fileobjs = [f for f in pcap_fileobjs if f]
    print(f"PCAPs downloaded: {len(pcap_fileobjs)}", flush=True)
    print(
        f"PCAP download time: {time.time() - pcap_create_time_start:.2f} seconds",
        flush=True,
    )

    print("Merging PCAPs...", flush=True)
    merge_time_start = time.time()
    safe_start = time_window_start.replace('/', '-').replace(':', '-')
    safe_end = time_window_end.replace('/', '-').replace(':', '-')
    filename = f"merge_{iccid}_{safe_start}_{safe_end}.pcap"
    merge_pcaps(pcap_fileobjs, details_list, output=filename)

    size = os.stat(filename).st_size
    size_mb = size / (1024 * 1024)
    size_mb_trunc = math.floor(size_mb * 100) / 100  # Truncate to 2 decimal places
    print(f"Merged file: {filename} ({size_mb_trunc:.2f} MB)", flush=True)
    print(f"Merge time: {time.time() - merge_time_start:.2f} seconds", flush=True)

    print(
        f"Total execution time: {time.time() - athena_time_start:.2f} seconds",
        flush=True,
    )
