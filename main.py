import pyshark
from collections import defaultdict


def parse_pcap(pcap_file):
    # Parse the PCAP file
    cap = pyshark.FileCapture(pcap_file)

    # Extract device information
    devices = set()
    conversations = defaultdict(list)

    for packet in cap:
        # Check if the packet has IP layer
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            # Add devices to our set
            devices.add(src_ip)
            devices.add(dst_ip)

            # Store conversation details
            protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'Unknown'
            timestamp = float(packet.sniff_timestamp)
            length = int(packet.length)

            conversation_key = (src_ip, dst_ip, protocol)
            conversations[conversation_key].append({
                'timestamp': timestamp,
                'length': length
            })

    return devices, conversations


import networkx as nx
import matplotlib.pyplot as plt


def create_network_diagram(devices, conversations):
    # Create a graph
    G = nx.Graph()

    # Add nodes (devices)
    for device in devices:
        G.add_node(device)

    # Add edges (conversations)
    for (src, dst, protocol), packets in conversations.items():
        # Calculate total bytes transferred
        total_bytes = sum(p['length'] for p in packets)
        # Calculate duration
        if packets:
            duration = max(p['timestamp'] for p in packets) - min(p['timestamp'] for p in packets)
        else:
            duration = 0

        # Add edge with attributes
        G.add_edge(src, dst, protocol=protocol,
                   packets=len(packets),
                   bytes=total_bytes,
                   duration=duration)

    # Draw the network
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_color='skyblue', node_size=1500, font_size=10)

    # Add edge labels
    edge_labels = {(u, v): f"{d['protocol']}\n{d['packets']} pkts"
                   for u, v, d in G.edges(data=True)}
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)

    plt.title("Network Conversation Diagram")
    plt.axis('off')
    plt.savefig('network_diagram.png')
    plt.close()

    return G