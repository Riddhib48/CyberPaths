import random

'''
Used to generate the CSC flags needed to hide the CSC traffic.
'''
def generateFlags(numberOfPkts):
        random.seed(567)
        normalFlags = []
        for x in range(numberOfPkts):
                pkt = random.random()
                if pkt >= 0.5176074282167548:
                        flags = "A"
                elif pkt < 0.5176074282167548 and pkt >= 0.12189413657242176:
                        flags = "PA"
                elif pkt < 0.12189413657242176 and pkt >= 0.04476427759929045:
                        flags = "S"
                elif pkt < 0.04476427759929045 and pkt >= 0.023467561835381623:
                        flags = "SA"
                elif pkt < 0.023467561835381623 and pkt >= 0.02307524280019084:
                        flags = "FA"
                elif pkt < 0.02307524280019084 and pkt >= 0.008174826483815309:
                        flags = "RA"
                elif pkt < 0.008174826483815309 and pkt >= 0.00749798113004563:
                        flags = "R"
                elif pkt < 0.00749798113004563 and pkt >= 0.006948671135401483:
                        flags = "FPA"
                elif pkt < 0.006948671135401483 and pkt >= 0.000002217088196718646:
                        flags = "F"
                elif pkt < 0.000002217088196718646 and pkt >= 0.0000004223025136606945:
                        flags = "FRA"
                elif pkt < 0.0000004223025136606945 and pkt >= 0.00000021115125683034726:
                        flags = "RPA"
                else:
                        flags = "FAU"
                normalFlags.append(flags)
        
        return normalFlags

'''
Used to make the htcl file for the CSC traffic.
'''     
def makeFile(IP1, IP2, normalTraffic):
        targetOne = IP1
        targetTwo = IP2
        
        regularFile = open('regular.htcl', 'w')
        
        regularFile.write('set target1 ' + targetOne + '\n')
        regularFile.write('set myaddr1 [hping outifa $target1]' + '\n')
        regularFile.write('set target2 ' + targetTwo + '\n')
        regularFile.write('set myaddr2 [hping outifa $target2]' + '\n')
        
        regularFile.write('set flags "')
        flags = ""
        for flag in normalTraffic:
                flags = flags + flag + ' '
                
        flags = flags.rstrip()
        
        regularFile.write(flags + '"' + '\n')
        
        regularFile.write('for {set ttl 0} {$ttl < ' + str(len(normalTraffic)) + '} {incr ttl} {' + '\n')
        regularFile.write('     set syn {}' + '\n')
        regularFile.write('     set count $ttl' + '\n')
        regularFile.write('     if {$count % 2 == 0} {' + '\n')
        
        regularFile.write('             append syn "ip(saddr=$myaddr1,daddr=$target1,ttl=$ttl)"' + '\n')
        regularFile.write('             if {[lindex $flags $ttl] eq \"B\"} {' + '\n')
        
        regularFile.write('                  append syn "+tcp(sport=123,dport=80)"' + '\n')
        regularFile.write('                  hping send $syn' + '\n')

        regularFile.write('             } else {' + '\n')

        regularFile.write('                  append syn "+tcp(sport=123,dport=80,flags=[lindex $flags $ttl])"' + '\n')
        regularFile.write('                  hping send $syn' + '\n')
        
        regularFile.write('     } } else {' + '\n')
        
        regularFile.write('             append syn "ip(saddr=$myaddr2,daddr=$target2,ttl=$ttl)"' + '\n')
        regularFile.write('             if {[lindex $flags $ttl] eq \"B\"} {' + '\n')
        
        regularFile.write('                  append syn "+tcp(sport=123,dport=80)"' + '\n')
        regularFile.write('                  hping send $syn' + '\n')

        regularFile.write('             } else {' + '\n')

        regularFile.write('                  append syn "+tcp(sport=123,dport=80,flags=[lindex $flags $ttl])"' + '\n')
        regularFile.write('                  hping send $syn' + '\n')
        
        regularFile.write('     }' + '\n')
        
        regularFile.write('} }')
        
def main():
        pktCount = eval(input("How many packets should hping3 send? (Ex: 300000) "))
        ifaceIP1 = input("What is the IP address of one of the interfaces you wish to send to? ")
        ifaceIP2 = input("What is the IP address of the other interface you whis to send to? ")
        
        makeFile(ifaceIP1, ifaceIP2, generateFlags(pktCount))

        print("Please check your directory in which this python script is located.")
        print("You should now see another file called regular.htcl.")
        print("This file can be ran with hping3 to generate regular traffic.")
        print("To run the new file simply issue the command: sudo hping3 exec regular.htcl")


main()
