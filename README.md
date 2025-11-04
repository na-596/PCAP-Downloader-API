PCAP Downloader — Publish package (publish-only subset)

This folder contains a sanitized, publish-only subset of a larger PCAP analysis project. The goal is to provide the core utilities needed to query session metadata (via Athena), fetch session PCAP data from configured collectors, and filter SCTP packets containing Diameter or other identifiers.

Key contents
- GUI: a lightweight interface and helpers (`gui.py`, `main_script.py`, `gui.py`).
- Athena helper: `athena_query.py` (wraps Athena/SQL queries used to find related identifiers).
- PCAP helpers: `merge.py` and `sctp_search_athena.py` (merge and filter PCAPs; the latter is the SCTP/Diameter-focused filter).
- `requirements.txt` lists the public Python packages needed.
- `.env.example` documents configuration variables (do not commit real secrets).

What the code (publish subset) can do
- Look up MSISDN/IMSI/IP information for a given ICCID using Athena (via `execute_athena_query`).
- Build safe queries against allowed collector endpoints and estimate data volume (CSV summary) before downloading any PCAPs.
- Download PCAP files into memory, parse SCTP packets, and heuristically extract Diameter request/response pairs and other payload matches (including TBCD-encoded numeric identifiers).
- Write a filtered PCAP containing only the matched packets.

sctp_search_athena.py — quick overview
- Purpose: given an ICCID and a time range, find PCAP sessions that contain relevant SCTP/Diameter traffic and save the filtered packets to a new PCAP.
- Inputs: iccid, start_time, stop_time (format: YYYY/MM/DD HH:MM:SS), max_process_size (bytes), output filename.
- Main steps:
  1. Query Athena for related identifiers (msisdn, imsi, ip, and a codeword/dcname).
  2. Combine Athena results with publish-only config (`IP_EXPRESSIONS` and `ALLOWED_CODEWORDS`).
  3. For each allowed (codeword, expression): fetch a CSV summary to estimate size.
  4. If size is acceptable, download the PCAP, parse in-memory, and filter SCTP/Diameter payloads using simple heuristics (raw substring, TBCD encoding, Diameter header parsing).
  5. Correlate Diameter requests and responses by end-to-end identifiers to include matching responses where appropriate.
