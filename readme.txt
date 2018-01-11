Description of the HW 4 - Network Security CS 508

Submitted by 

Reference - 
1) http://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-scapy-nfqueue.html
2) http://www.thegeekstuff.com/2013/06/python-list/?utm_source=feedly
3) https://docs.python.org/3/tutorial/datastructures.html
4) https://thepacketgeek.com/scapy-p-09-scapy-and-dns/

Source file - 
1) dns_inject.py
2) dns_inject_detection.py
Output file - NA

How to Build:---->
NA

How to Clean build:---->
NA

Output File - NA

Help---->
dns_inject [-i interface] [-h hostnames] expression

-i interface              -> Ethernet Interface to be used for DNS packet sniffing.
							If not provided default interface is used.
-h hostnames              -> File giving the list of host, to be tracked and DNS request to these host, will be attacked.
							If it is not provided all DNS host request are attacked.
Expression                -> BPF filter
							If it is not provided - default - "udp dst port 53"

dns_inject_detection [-i interface] [-r pcapfilename] expression

-i interface              -> Ethernet Interface to be used for DNS packet sniffing check.
							If not provided default interface is used.
-r pcapfilename           -> Pcap file which contains the DNS packets which needs parsing and DNS injection attack needs detected.
							If it is not provided Ethernet Interface is used.
Expression                -> BPF filter
							If it is not provided - default - "udp dst port 53"


To start the DNS inject
#sudo python dns_inject.py -i ens33 -h hostnames

Explaination
-> Sniffing for DNS query packets in ens33 interface and attacking the packets which belong to this host.

To start the DNS inject detection
#sudo python dns_inject_detection.py -i ens33 "udp dst port 53"

Explaination
-> Checking for DNS injection attack on the interface in promisicous mode.



Description of the Implementation and design ----->

dns_inject.py
Functions
1) Basic python command parsing
2) sniffdns() -> Handles all the DNA packet parsing and injection of the DNS packet.
3) 

dns_inject_detection.py
1) Basic python command parsing
2) sniffdnsinjectdetect() -> Handles all the DNA packet parsing and stores the old packet in a list.
							Compares the current with the list items and dumps the output if a duplicate packet is detected.


OS Version tested - Ubuntu 16.04 and python 2.7

The code sample used are updated in the reference.





