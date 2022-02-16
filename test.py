import unittest
from main import parse_pcap, create_network_diagram


class TestNetworkAnalysis(unittest.TestCase):

    def settingUp(self):
        self.pcap_file = 'pcap_files/sniff1.pcap'

    def test_parse_pcap_devices(self):
        devices, _ = parse_pcap(self.pcap_file)
        self.assertTrue(isinstance(devices, set))

    def test_create_network_diagram(self):
        devices, conversations = parse_pcap(self.pcap_file)
        network_graph = create_network_diagram(devices, conversations)
        self.assertTrue(network_graph)  # Ensure the network graph is created
        self.assertGreater(len(network_graph.nodes), 0)  # Ensure nodes (devices) are present


if __name__ == '__main__':
    unittest.main()
