

from scapy.all import *
import sys


pcapfilename = None
expression= None
interface = None
jump = 0

dnspacketlist = []


#20160406-15:08:49.205618  DNS poisoning attempt 
#TXID 0x5cce Request www.example.com
#Answer1 [List of IP addresses]
#Answer2 [List of IP addresses]

def sniffdnsinjectdetect(pkt):
	#if IP in pkt:
	if pkt.haslayer(IP):
		#pkt.show()
		#ip_src = pkt[IP].src;
		#ip_dst = pkt[IP].dst;
		if pkt.haslayer(DNS):
			#pkt.show()
			#if pkt.haslayer(DNSRR):
			#pkt.show()
			for savedpkt in dnspacketlist:	
				#print "Dst ", savedpkt[IP].dst , pkt[IP].dst				## 0 elements skip and push to list
				if (savedpkt[IP].dst == pkt[IP].dst):		## same destination check
					#pkt.show()
					#print "id ", savedpkt[DNS].id , pkt[DNS].id
					if (savedpkt[DNS].id == pkt[DNS].id):	## txid should be same
						#pkt.show()
						if(savedpkt[DNSRR].rdata != pkt[DNSRR].rdata):	## IP should be different in the reply
							datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')
							qname = pkt[DNS].qd.qname
							print "DNS poisoning attempt"
							print "TXID ", pkt[DNS].id, " Request ",qname.rstrip('.')
							print "Answer1 [", savedpkt[DNSRR].rdata, "]"
							print "Answer2 [", pkt[DNSRR].rdata, "]"
			dnspacketlist.insert(0, pkt)
			#pkt.show()
			#print "length ", len(dnspacketlist)
			if(len(dnspacketlist) > 8):
				dnspacketlist.pop()


				#Packet is a valid DNS response packet

				#datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')

				#print str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + pkt.getlayer(DNS).qd.qname + ")"
				#packethostname = pkt[DNSQR].qname.rstrip('.')
				#packethostname1 = pkt[DNSQR].qname
				#packethostname = packethostname1.rstrip('.')
				#print packethostname
				#print "haskey" , myList.has_key(packethostname)
				#if(anyip == 1):
				#	local_ip = "127.0.0.1"
				#elif(myList.has_key(packethostname) == True):
				#	local_ip = myList[packethostname]
					#if(item == 0)
					#print item
				#spfResp = IP(dst=pkt[IP].src, src=pkt[IP].dst)\
				#/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)\
				#/DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata=local_ip)\
				#/DNSRR(rrname=pkt[DNSQR].qname,rdata=local_ip))
				#send(spfResp, verbose=0)
				#spfResp.show()
				#print "Spoofed DNS Packet Sent"


print "DNS Injection Detection Program", len(sys.argv)

if(len(sys.argv) > 6):
	print "Usage: dnsdetect [-i interface] [-r tracefile] expression"
	sys.exit()

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
	elif(argv == "-r"):
		pcapfilename = sys.argv[index + 1]
		#print "host file = ", hostfilename
		jump = 1
	else:
		expression = argv
		print "Exp = ", expression
	#print index, argv

if(expression == None):
	expression = "udp dst port 53"

if(interface != None and pcapfilename != None):
	print "Usage: dnsdetect [-i interface] [-r tracefile] expression"
	print "Both interface and tracefile options are not acceptable"
	sys.exit()

if(interface == None and pcapfilename != None):
	print "Parsing the pcap file = ", pcapfilename
	print "final exp = ", expression
	sniff(filter=expression, prn=sniffdnsinjectdetect, store=0, offline = pcapfilename)
elif(interface != None and pcapfilename == None):
	print "Interface = ", interface
	print "final exp = ", expression
	sniff(iface=interface, filter=expression, prn=sniffdnsinjectdetect, store=0)
else:
	print "Interface = default"
	print "final exp = ", expression
	sniff(filter=expression, prn=sniffdnsinjectdetect, store=0)


	
#if(hostfilename == None):
#	anyip = 1;
#if(len(sys.argv) == 1):
#	print "Running with default interface and no host parsing or expression"


#sniff(iface=interface, filter=expression, prn=querysniff, store=0)
