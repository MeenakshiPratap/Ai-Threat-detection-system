from scapy.all import sniff
from queue import Queue

packet_queue = Queue()

def capture_packet(packet):
    packet_queue.put(packet)

def start_sniffing():
    sniff(prn=capture_packet, store=0)
