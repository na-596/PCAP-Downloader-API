import dpkt
import socket


def merge_pcaps(pcap_fileobjs, details_list, output="merge.pcap"):
    """Merge multiple PCAP file-like objects and filter packets of interest.

    The function reads all packets from the provided file-like objects, sorts
    them by timestamp, and applies a simple inclusion heuristic:
    - include if source/destination IP matches one of the `details_list`
    - include if any of the `details_list` byte strings appear in the packet
    - special handling for RADIUS (UDP) messages where requests/responses are correlated

    Returns the output filename written.
    """
    valid_identifiers = {}
    all_packets = []
    packet_no = 0
    one_flag = False
    four_flag = False

    def extract_eth(pkt_data):
        try:
            return dpkt.ethernet.Ethernet(pkt_data)
        except Exception:
            return None

    def extract_ip_info(eth):
        # Return (ip_layer, src_ip_str, dst_ip_str) for IPv4/IPv6; otherwise None
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            return ip, src, dst
        elif isinstance(eth.data, dpkt.ip6.IP6):
            ip = eth.data
            src = socket.inet_ntop(socket.AF_INET6, ip.src)
            dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
            return ip, src, dst
        return None, None, None

    def extract_radius_info(udp_payload):
        # Basic RADIUS header parsing: code (1 byte), identifier (1 byte), length (2 bytes)
        if len(udp_payload) < 20:
            return None, None
        code = udp_payload[0]
        identifier = udp_payload[1]
        length = int.from_bytes(udp_payload[2:4], "big")
        if length <= len(udp_payload):
            return code, identifier
        return None, None

    # Read packets from every provided file-like object
    for fobj in pcap_fileobjs:
        fobj.seek(0)
        pcap = dpkt.pcap.Reader(fobj)
        for ts, buf in pcap:
            all_packets.append((ts, buf))

    # Merge by timestamp
    all_packets.sort()

    filtered_packets = []

    for ts, buf in all_packets:
        packet_no += 1
        eth = extract_eth(buf)
        if eth is None:
            continue

        include = False
        pkt_bytes = buf

        ip_layer, src_ip, dst_ip = extract_ip_info(eth)

        # IP filtering: include if either endpoint is in the details list
        if src_ip in details_list or dst_ip in details_list:
            include = True

        # Byte-level search for identifiers (msisdn/imsi etc.)
        for d in details_list:
            if d.encode() in pkt_bytes:
                include = True
                break

        # RADIUS handling: correlate requests/responses by identifier
        udp_layer = None
        if ip_layer and isinstance(ip_layer.data, dpkt.udp.UDP):
            udp_layer = ip_layer.data
            code, ident = extract_radius_info(udp_layer.data)
            if code is not None:
                # If we have a matching response code and previously saw a request
                if code in [2, 3] and ident in valid_identifiers and one_flag:
                    include = True
                    valid_identifiers.pop(ident)
                    one_flag = False
                if code == 5 and ident in valid_identifiers and four_flag:
                    include = True
                    valid_identifiers.pop(ident)
                    four_flag = False

                # If this packet is an Access-Request (1) or Accounting-Request (4)
                # and it's included by the heuristic, remember it so we can match responses
                if include and code == 1:
                    valid_identifiers[ident] = packet_no
                    one_flag = True
                if include and code == 4:
                    valid_identifiers[ident] = packet_no
                    four_flag = True

        if include:
            filtered_packets.append((ts, buf))

    # Report any unmatched requests (useful diagnostics)
    if valid_identifiers:
        print("Unmatched RADIUS requests (no response):")
        for ident, pkt_no in valid_identifiers.items():
            print(f"Id: {ident}, Packet No: {pkt_no}")
    else:
        print("All RADIUS requests matched")

    # Write selected packets to disk
    with open(output, "wb") as f_out:
        writer = dpkt.pcap.Writer(f_out)
        for ts, buf in filtered_packets:
            writer.writepkt(buf, ts)

    print(f"DPKT merge complete: {output}")
    return output
