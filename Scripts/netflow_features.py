from collections import defaultdict

def detect_frequency_of_connections(netflow_data, keys, threshold=10):
    ip_connection_count = defaultdict(int)
    suspicious_ips = []

    for flow in netflow_data:
        src_ip = flow.get(keys["src_ip"])
        ip_connection_count[src_ip] += 1

        if ip_connection_count[src_ip] > threshold:
            suspicious_ips.append(src_ip)

    return suspicious_ips

def detect_ip_reuse(netflow_data, keys, threshold=3):
    ip_reuse = defaultdict(lambda: defaultdict(int))
    suspicious_ips = []

    for flow in netflow_data:
        src_ip = flow.get(keys["src_ip"])
        dst_ip = flow.get(keys["dst_ip"])
        ip_reuse[src_ip][dst_ip] += 1

        if ip_reuse[src_ip][dst_ip] > threshold:
            suspicious_ips.append(src_ip)

    return suspicious_ips

def detect_p2p_traffic(netflow_data, keys, threshold=5):
    ip_peer_connections = defaultdict(set)
    suspicious_ips = []

    for flow in netflow_data:
        src_ip = flow.get(keys["src_ip"])
        dst_ip = flow.get(keys["dst_ip"])
        ip_peer_connections[src_ip].add(dst_ip)

        if len(ip_peer_connections[src_ip]) > threshold:
            suspicious_ips.append(src_ip)

    return suspicious_ips

def detect_packet_size_anomalies(netflow_data, keys, threshold=1000 ):
    ip_packet_sizes = defaultdict(list)
    suspicious_ips = []

    for flow in netflow_data:
        src_ip = flow.get(keys["src_ip"])
        packet_size = flow.get(keys["bytes"], 0)
        ip_packet_sizes[src_ip].append(packet_size)

        if len(ip_packet_sizes[src_ip]) > threshold:
            suspicious_ips.append(src_ip)

    return suspicious_ips
