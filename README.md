# PCAP Downloader — Publish package (publish-only subset)

This folder contains a sanitized, publish-only subset of a larger PCAP analysis project. The goal is to provide the core utilities and demonstrate building full-stack, API/service integration and advanced networking principles.

---

## Operation Status Note

The **Graphical User Interface (`gui.py`) will still launch and run** using `customtkinter`, demonstrating the application's client-side structure and responsiveness. However, its core functions, querying Athena, fetching portfolio tokens, and downloading data from ElasticSearch, will obviously fail because all required authentication tokens and endpoints have been intentionally removed and replaced with placeholder environment variables.

---

## Project Core Concept

This application is designed to efficiently **retrieve, merge, and filter** raw network packet capture (PCAP) data associated with a specific device (identified by **ICCID**) over a user-defined time window.

### The Pipeline:
1.  **Identifier Lookup (Athena/External API):** Use the ICCID to query a cloud data warehouse (AWS Athena via `boto3`) and an external service (via `requests`) to retrieve associated metadata, such as MSISDN, IMSI, and relevant service IP addresses, over the specified time window.
2.  **PCAP Retrieval (ElasticSearch):** Use the retrieved IPs and service identifiers to query a remote ElasticSearch-hosted collector to fetch multiple raw PCAP files.
3.  **Local Analysis and Merge:** Download the PCAPs into memory (`io.BytesIO`), then use `dpkt` to parse the packets and apply a custom filtering heuristic.
4.  **Output:** Generate a single, merged, time-sorted PCAP file containing only the packets relevant to the user's request.

---

## ⚙️ Key Functionality and Components

| File | Description | Technologies Demonstrated |
| :--- | :--- | :--- |
| `gui.py` | **Graphical User Interface (GUI)** built with `customtkinter`. It redirects terminal output into the UI text widget, offers time window presets, and executes the search/merge process on a background thread to maintain responsiveness. | `customtkinter`, `threading` |
| `main_script.py` | **Core Execution Flow.** Orchestrates Athena query, fetches necessary ElasticSearch URLs, checks the estimated file size via concurrent CSV fetching, downloads PCAPs concurrently, and manages the final merge process. | `requests`, `threading`, `urllib.parse`, `HTTPDigestAuth` |
| `merge.py` | **Low-Level Packet Analysis.** Implements packet merging, time-sorting, IP filtering, byte-level filtering, and special correlation logic for RADIUS (UDP) request/response pairs. | `dpkt`, `socket` |
| `sctp_search_athena.py` | **SCTP/Diameter-Specific Filtering.** Contains logic for Diameter header parsing, TBCD (telephony BCD) encoding/matching, and uses a thread pool to concurrently process data from various collector endpoints. | `dpkt`, `Diameter Protocol Parsing`, `concurrent.futures` |
| `athena_query.py` | **Cloud Data Retrieval.** Handles the parameterized construction and polling execution of the AWS Athena SQL query using `boto3`. It retrieves the device identifiers required for PCAP searching. | `boto3`, `botocore`, `SQL` |

---

## 🚀 Environment Setup

### Requirements
The key public dependencies can be installed via the following:

```bash
pip install -r requirements.txt

