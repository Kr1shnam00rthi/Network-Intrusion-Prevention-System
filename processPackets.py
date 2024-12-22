""" Module to capture packets on a specified interface and extract details from each. """

from scapy.all import *
from scapy.layers.http import HTTPRequest
from netfilterqueue import NetfilterQueue
import subprocess
import storeLogs
import matchRules

class processPackets(matchRules.matchRules , storeLogs.storeLogs):
    
    def __init__(self):
        
        self.nfqueue = NetfilterQueue()

    def ProcessPackets(self,packet):

        """ Function to Extract key parameter from a packet """

        scapy_packet = IP(packet.get_payload())
    
        packet_info = {
            'protocol': None,
            'source_ip': None,
            'destination_ip': None,
            'source_port': None,
            'destination_port': None,
            'flags': None,
            'icode': None,
            'itype': None,
            'payload': None,
        }
    
        if scapy_packet.haslayer(IP) and (scapy_packet.haslayer(TCP) or scapy_packet.haslayer(UDP) or scapy_packet.haslayer(ICMP)):
        
            packet_info['source_ip'] = scapy_packet[IP].src
            packet_info['destination_ip'] = scapy_packet[IP].dst
    
            if scapy_packet.haslayer(TCP):
                packet_info['protocol'] = 'tcp'
                packet_info['source_port'] = scapy_packet[TCP].sport
                packet_info['destination_port'] = scapy_packet[TCP].dport
                packet_info['flags'] = str(scapy_packet[TCP].flags)

            elif scapy_packet.haslayer(UDP):
                packet_info['protocol'] = 'udp'
                packet_info['source_port'] = scapy_packet[UDP].sport
                packet_info['destination_port'] = scapy_packet[UDP].dport

            elif scapy_packet.haslayer(ICMP):
                packet_info['protocol'] = 'icmp'
                packet_info['icode'] = str(scapy_packet[ICMP].code)
                packet_info['itype'] = str(scapy_packet[ICMP].type)
            
            if scapy_packet.haslayer(Raw):
                payload = scapy_packet[Raw].load.decode('utf-8', errors='ignore')
                packet_info['payload'] = f"""{payload}"""
                
            self.TrafficLogs(packet_info)
            result = self.MatchRules(packet_info)
            if result == 1:
                packet.drop()
            else:
                packet.accept()

    def StartQueueing(self):

        subprocess.run(["sudo","iptables","-I","INPUT","-j","NFQUEUE","--queue-num","0"])
        subprocess.run(["sudo","iptables","-I","OUTPUT","-j","NFQUEUE","--queue-num","0"])

        try:
            self.nfqueue.bind(0,self.ProcessPackets)
            print("Engine Started Processing Pakects !!!\n")
            self.nfqueue.run()
    
        except KeyboardInterrupt:
            print("Exiting....")
            print("Engine Truned Off...")
            self.nfqueue.unbind()
            subprocess.run(["sudo","iptables","-F"])
    
        finally:
            self.nfqueue.unbind()
            subprocess.run(["sudo","iptables","-F"])

processpackets = processPackets()
