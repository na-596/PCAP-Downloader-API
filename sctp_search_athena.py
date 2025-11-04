import dpkt
import json
from datetime import datetime
import urllib3
import urllib.parse
import requests
import csv
import os
from io import BytesIO
from requests.auth import HTTPDigestAuth
from athena_query import execute_athena_query
from config import ES_HOST_TEMPLATE, ES_USER, ES_PASS, IP_EXPRESSIONS, ALLOWED_CODEWORDS
import concurrent.futures
import threading

# Suppress insecure request warnings because requests calls in this module
# intentionally disable TLS verification in some contexts (verify=False).
# NOTE: disabling warnings does not make the requests secure; prefer configuring
# certificate verification in production deployments.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def filter_sctp_diameter(
    iccid,
    start_time,
    stop_time,
    max_process_size,
    output="filtered_sctp_diameter.pcap",
):
    """Filter SCTP PCAP sessions obtained from an ElasticSearch-hosted collector.

    This function queries an Athena helper to retrieve identifiers (MSISDN/IMSI/IP)
    related to the provided ICCID, then uses configured expressions to query a
    remote session store (CSV + PCAP endpoints). It downloads PCAP data into
    memory, parses SCTP packets, looks for Diameter payloads or numeric/TBCD
    encodings matching the keywords, and writes matching packets to a new PCAP
    file.

    Returns
    - list of (timestamp, raw_packet) tuples from matching packets if called
      internally; the function also writes a PCAP file to `output` on completion.
    """
    def extract_ip_info(eth):
        if isinstance(eth.data, dpkt.ip.IP):
            return eth.data
        elif isinstance(eth.data, dpkt.ip6.IP6):
            return eth.data
        return None

    def parse_diameter_header(data: bytes):
        if len(data) < 20:
            return None
        version = data[0]
        if version != 1:
            return None
        msg_length = int.from_bytes(data[1:4], "big")
        flags = data[4]
        command_code = int.from_bytes(data[5:8], "big")
        application_id = int.from_bytes(data[8:12], "big")
        hop_by_hop = int.from_bytes(data[12:16], "big")
        end_to_end = int.from_bytes(data[16:20], "big")
        return {
            "length": msg_length,
            "flags": flags,
            "command_code": command_code,
            "application_id": application_id,
            "hop_by_hop": hop_by_hop,
            "end_to_end": end_to_end,
        }

    def tbcd_encode(digits: str) -> bytes:
        """Encode a numeric string into TBCD (telephony BCD) as used by MAP for IMSI/MSISDN.
        Example: '12345' -> bytes([0x21, 0x43, 0xF5])
        """
        nibbles = []
        for ch in digits:
            if not ch.isdigit():
                return b""
            nibbles.append(int(ch))
        out = bytearray()
        for i in range(0, len(nibbles), 2):
            low = nibbles[i]
            high = 0xF if i + 1 >= len(nibbles) else nibbles[i + 1]
            out.append((high << 4) | low)
        return bytes(out)

    def payload_contains_tbcd(payload: bytes, digits: str) -> bool:
        if not digits or not digits.isdigit():
            return False
        encoded = tbcd_encode(digits)
        if not encoded:
            return False
        return encoded in payload

    # Containers used during search
    keywords = []       # values to search for in payloads (msisdn, imsi, ip)
    codewords = []      # data center / code identifiers returned by Athena
    configs = []        # pairs of (codeword, expression) after config filtering
    output_packets = [] # matched packets collected for eventual write-out

    # Query Athena (project-specific helper) to get identifiers for the ICCID.
    # The returned rows are expected to include: dcntitle, msisdn, imsi, ip, start/stop
    athena_data = execute_athena_query(iccid)
    for dcntitle, msisdn, imsi, ip, athena_start_time, athena_stop_time in athena_data:
        keywords.extend([msisdn, imsi, ip])
        codewords.append(dcntitle)

    # Load publish-only configuration constants (should be sanitized values)
    expressions = IP_EXPRESSIONS
    allowed_codewords = ALLOWED_CODEWORDS

    # Build the list of (codeword, expression) pairs to query. We only include
    # codewords that are present in the allowed list to avoid contacting
    # internal/unauthorized endpoints.
    configs.extend((cw, exp) for cw in codewords if cw in allowed_codewords for exp in expressions)

    def find_output_packets(code, expression):
        print(f"Processing {code} with expression: {expression}")

        # Convert human-readable times to epoch seconds for the remote API
        start_ts = int(datetime.strptime(start_time, "%Y/%m/%d %H:%M:%S").timestamp())
        stop_ts = int(datetime.strptime(stop_time, "%Y/%m/%d %H:%M:%S").timestamp())
        encoded_expr = urllib.parse.quote(expression)

        base_url = f"https://{ES_HOST_TEMPLATE.format(code=code)}"
        query_params = f"expression={encoded_expr}&startTime={start_ts}&stopTime={stop_ts}&length=10000000"
        csv_url = f"{base_url}/sessions.csv?{query_params}"
        pcap_url = f"{base_url}/sessions.pcap?{query_params}"
        # Debug: show the PCAP URL constructed for this code/expression
        print(pcap_url)

        # Read CSV
        username = ES_USER
        password = ES_PASS

        # First, fetch a CSV summary describing sessions/byte counts. This is used
        # to estimate total size before attempting to download the (possibly large) PCAP.
        print("Fetching CSV...")
        resp = requests.get(csv_url, stream=True, verify=False, auth=HTTPDigestAuth(username, password))
        if resp.status_code != 200:
            raise RuntimeError(f"Error fetching CSV: {resp.status_code}\n{resp.text[:500]}")

        # Iterate CSV lines streamed from the remote host. We don't want to store the
        # whole CSV in memory if it's large, so we stream and tally only the relevant columns.
        reader = csv.reader(resp.iter_lines(decode_unicode=True))
        header = next(reader, None)
        if not header:
            raise RuntimeError("CSV missing header.")
        header_map = {name.strip().lower(): idx for idx, name in enumerate(header)}
        bytes_idx = header_map.get("bytes")
        databytes_idx = header_map.get("data bytes")
        if bytes_idx is None or databytes_idx is None:
            raise RuntimeError("Missing 'Bytes' or 'Data bytes' in CSV.")

        total_bytes = 0
        row_count = 0
        for row in reader:
            row_count += 1
            try:
                total_bytes += int(row[bytes_idx]) + int(row[databytes_idx])
            except Exception:
                continue
            if total_bytes > max_process_size:
                print(
                    f"Data exceeds size limit. Exiting."
                )
                return

        print("Total:", total_bytes)
        size_mb = total_bytes / (1024 * 1024)
        print(f"CSV processed: {row_count} rows, ~{size_mb:.2f} MB")
        if total_bytes == 0:
            print("CSV has no data, skipping PCAP fetch.")
            return


        # If the size looks safe, download entire PCAP into memory. We parse it
        # from memory (BytesIO) rather than saving raw PCAP to disk first.
        print("Fetching PCAP into memory (no file write)...")
        pcap_resp = requests.get(pcap_url, verify=False, auth=HTTPDigestAuth(username, password), timeout=900)
        if pcap_resp.status_code != 200:
            raise RuntimeError(f"Failed to download PCAP: {pcap_resp.status_code}")
        pcap_bytes = pcap_resp.content
        print(f"PCAP size: {len(pcap_bytes)/(1024*1024)} MB")
        # Basic sanity-check: a PCAP global header is larger than a few bytes.
        if len(pcap_bytes) < 24:
            preview = pcap_bytes[:200].decode(errors="ignore") if pcap_bytes else ""
            raise RuntimeError(
                f"Empty or invalid PCAP payload (len={len(pcap_bytes)}). URL: {pcap_url}. Preview: {preview}"
            )

        # Parse PCAP and filter packets of interest.
        # We maintain a small state (matched_requests) to correlate Diameter
        # request/response pairs based on end-to-end and hop-by-hop identifiers.
        matched_requests = {}

        pcap = dpkt.pcap.Reader(BytesIO(pcap_bytes))

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                # Skip malformed frames
                continue

            ip = extract_ip_info(eth)
            # We only care about SCTP packets here
            if not ip or not isinstance(ip.data, dpkt.sctp.SCTP):
                continue

            sctp = ip.data
            include_packet = False

            # Each SCTP packet can contain multiple chunks; inspect DATA chunks
            for chunk in sctp.chunks:
                if chunk.type != dpkt.sctp.DATA:
                    continue

                # Skip tiny payloads that can't contain Diameter/TBCD data
                if len(chunk.data) < 12:
                    continue
                # User payload normally starts after the 12-byte SCTP DATA header
                sctp_user_payload = chunk.data[12:]

                header = parse_diameter_header(sctp_user_payload)
                if header:  # Likely a Diameter message
                    # Quick heuristic: if any keyword bytes appear in the payload,
                    # mark it for inclusion. This is a best-effort filter.
                    for kw in keywords:
                        if kw.encode() in sctp_user_payload:
                            include_packet = True
                            break

                    is_request = bool(header["flags"] & 0x80)
                    hop_id = header["hop_by_hop"]
                    end_to_end = header["end_to_end"]
                    command_code = header["command_code"]

                    # If this is a request with a matching keyword, remember the
                    # hop-by-hop value so that we can include the matching response
                    # when it arrives (correlate using end-to-end and command code).
                    if include_packet and is_request:
                        entry = matched_requests.setdefault(end_to_end, {"command_code": command_code, "hop_ids": set()})
                        entry["hop_ids"].add(hop_id)
                    elif not is_request:
                        # For responses, check there was a corresponding request
                        entry = matched_requests.get(end_to_end)
                        if entry and entry.get("command_code") == command_code:
                            include_packet = True
                            matched_requests.pop(end_to_end, None)

                else:
                    # Not a Diameter header — use fallback checks: raw substring
                    # matching and TBCD decoding for numeric identifiers
                    for kw in keywords:
                        kw_str = kw if isinstance(kw, str) else str(kw)
                        kw_bytes = kw_str.encode(errors="ignore")
                        if kw_bytes and kw_bytes in sctp_user_payload:
                            include_packet = True
                            break
                        if kw_str and kw_str.isdigit() and payload_contains_tbcd(sctp_user_payload, kw_str):
                            include_packet = True
                            break

            if include_packet:
                output_packets.append((ts, buf))
        return output_packets

    # Track which codewords have already produced matches to avoid duplicate work
    code_done = {code: False for code, _ in configs}
    lock = threading.Lock()
    all_output_packets = []
    def wrapped_find_output_packets(code, expr):
        with lock:
            if code_done.get(code, False):
                print(f"[SKIP] {code} - {expr}: already found packets for this code.")
                return []
        packets = find_output_packets(code, expr)
        if packets:
            with lock:
                code_done[code] = True
            print(f"[INCLUDE] {code} - {expr}: included {len(packets)} packets.")
        else:
            print(f"[NO PACKETS] {code} - {expr}: no packets included.")
        return packets
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(wrapped_find_output_packets, code, expr)
            for code, expr in configs
        ]
        for future in concurrent.futures.as_completed(futures):
            packets = future.result()
            if packets:
                all_output_packets.extend(packets)

    # Write filtered packets to new pcap ordered by timestamp
    all_output_packets.sort(key=lambda x: x[0])
    print("Writing out packets to PCAP...")
    with open(output, "wb") as f_out:
        writer = dpkt.pcap.Writer(f_out)
        for ts, buf in all_output_packets:
            writer.writepkt(buf, ts)

    print(f"[+] Wrote {len(all_output_packets)} packets to {output}")
