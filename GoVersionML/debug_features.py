import pandas as pd
import sys

df = pd.read_json('../test_netflow.json')
df['time'] = pd.to_datetime(df['first'], format='%Y-%m-%dT%H:%M:%S.%f', errors='coerce')
df['time_window'] = df['time'].dt.floor('5min')
df['duration_sec'] = (pd.to_datetime(df['last'], format='%Y-%m-%dT%H:%M:%S.%f', errors='coerce') - df['time']).dt.total_seconds().clip(lower=0)
df['is_tcp'] = (df['proto'] == 6).astype(int)
df['is_udp'] = (df['proto'] == 17).astype(int)
df['is_icmp'] = (df['proto'] == 1).astype(int)
df['well_known_port'] = ((df['dst_port'] > 0) & (df['dst_port'] < 1024)).astype(int)
df['syn_only'] = (df['tcp_flags'].str.contains('S', na=False) & ~df['tcp_flags'].str.contains('A|F|R', na=False)).astype(int)
df['has_rst'] = df['tcp_flags'].str.contains('R', na=False).astype(int)
df = df.sort_values(['src4_addr', 'dst4_addr', 'dst_port', 'first'])
df['iat'] = df.groupby(['src4_addr', 'dst4_addr', 'dst_port', 'time_window'])['time'].diff().dt.total_seconds().fillna(0).astype('float32')
agg_funcs = {
    'first': 'count', 'dst4_addr': 'nunique', 'dst_port': 'nunique', 'in_bytes': 'sum', 'in_packets': 'sum',
    'is_tcp': 'sum', 'is_udp': 'sum', 'is_icmp': 'sum', 'syn_only': 'sum', 'has_rst': 'sum',
    'well_known_port': 'sum', 'duration_sec': 'mean', 'iat': ['mean', 'var']
}
grouped = df.groupby(['src4_addr', 'time_window']).agg(agg_funcs)
grouped.columns = ['_'.join(filter(None, col)).strip() for col in grouped.columns.values]
grouped = grouped.reset_index().rename(columns={'first_count': 'flow_count', 'dst4_addr_nunique': 'unique_dst_ips', 'dst_port_nunique': 'unique_dst_ports', 'in_bytes_sum': 'total_bytes', 'in_packets_sum': 'total_packets', 'is_tcp_sum': 'tcp_count', 'is_udp_sum': 'udp_count', 'is_icmp_sum': 'icmp_count', 'syn_only_sum': 'count_syn_only', 'has_rst_sum': 'count_rst', 'well_known_port_sum': 'count_well_known_ports', 'duration_sec_mean': 'avg_duration', 'iat_mean': 'iat_mean', 'iat_var': 'iat_variance'})
grouped['avg_bytes_per_flow'] = grouped['total_bytes'] / grouped['flow_count']
grouped['avg_packets_per_flow'] = grouped['total_packets'] / grouped['flow_count']
grouped['pct_tcp'] = (grouped['tcp_count'] / grouped['flow_count']) * 100
grouped['pct_udp'] = (grouped['udp_count'] / grouped['flow_count']) * 100
grouped['pct_icmp'] = (grouped['icmp_count'] / grouped['flow_count']) * 100
grouped['pct_well_known_ports'] = (grouped['count_well_known_ports'] / grouped['flow_count']) * 100
grouped['pct_high_ports'] = 100.0 - grouped['pct_well_known_ports']
grouped['avg_payload_per_packet'] = grouped['total_bytes'] / grouped['total_packets'].clip(lower=1)
grouped['pct_syn_only'] = (grouped['count_syn_only'] / grouped['flow_count']) * 100
grouped['pct_rst'] = (grouped['count_rst'] / grouped['flow_count']) * 100
grouped['iat_cv'] = (grouped['iat_variance'] ** 0.5) / grouped['iat_mean'].replace(0, pd.NA)
grouped['iat_cv'] = grouped['iat_cv'].fillna(0)
port_symmetry_dict = {}
for src in grouped['src4_addr'].unique():
    src_mask = df['src4_addr'] == src
    outbound_ports = set(df[src_mask]['dst_port'].dropna())
    dst_mask = df['dst4_addr'] == src
    inbound_ports = set(df[dst_mask]['dst_port'].dropna())
    port_symmetry_dict[src] = len(outbound_ports.intersection(inbound_ports))
grouped['port_symmetry'] = grouped['src4_addr'].map(port_symmetry_dict)
grouped['ip_port_ratio'] = grouped['unique_dst_ips'] / grouped['unique_dst_ports'].clip(lower=1)

cols = ['flow_count', 'unique_dst_ips', 'unique_dst_ports', 'total_bytes', 'total_packets', 'avg_bytes_per_flow', 'avg_packets_per_flow', 'pct_tcp', 'pct_udp', 'pct_icmp', 'pct_well_known_ports', 'pct_high_ports', 'avg_duration', 'iat_mean', 'iat_variance', 'port_symmetry', 'ip_port_ratio', 'avg_payload_per_packet', 'pct_syn_only', 'pct_rst', 'iat_cv']

ips = ['185.100.233.168', '212.8.250.225']
legacy = grouped[grouped['src4_addr'].isin(ips)]

for idx, row in legacy.iterrows():
    if row['flow_count'] >= 5:
        print(f'\n--- Python Feature Array for {row["src4_addr"]} (Window: {row["time_window"]}) ---')
        for i, c in enumerate(cols):
            print(f'  [{i}] {c}: {row[c]:.4f}')
