import re
from  scapy.all import *
from datetime import datetime
import time

file = open("csc.txt", "r")

tcpFlags = ['F', 'S', 'R', 'P', 'A', 'U']

routeOne = IP(dst = "10.10.10.3")
routeTwo = IP(dst = "10.10.10.7")

startTime = datetime.now()
count = 0
binaryString = ' '.join(format(ord(i), 'b').zfill(8) for i in file.read()).replace(' ', '')

sixBits = [binaryString[i:i+6] for i in range(0, len(binaryString), 6)]
if len(sixBits[-1]) != 6:
	fillerBits = '0' * (6 - len(sixBits[-1]))
        sixBits[-1] = sixBits[-1] + fillerBits

for combination in sixBits:
	setFlags = ""
        for x in range(6):
        	if combination[x] == "1":
                	setFlags = setFlags + tcpFlags[x]

        piece = TCP(sport = 1024, dport = 80, flags = setFlags, seq = 12345)
        if count % 2 == 0:
        	sendp(Ether()/routeOne/piece, iface = "eth2")
        else:
                sendp(Ether()/routeTwo/piece, iface = "eth1")

        count = count + 1

print "Time it took to send: ", datetime.now() - startTime
