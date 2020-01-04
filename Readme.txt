Implemented sniffer on raw sockets.
Usage:
sudo python3 sniffer
Sniffer will capture icmp,udp,tcp packets from all interfaces
To specify an interface, use -i
output settings:
-v more detailed output
-l display link level data
-d display data
--color colorize incoming / outgoing packets
Sniffer can write data on pcap format, for this you need to specify key pcap
pcap settings:
-n set file name
-t set time
-fp set max packets in file
-s set max size
Sniffer can filter packets, for this you need to specify key -c and then condition
Available commands:
1.proto - with this command you can set the transport layer protocol.Supported : tcp, icmp, udp
Example: proto == tcp
2.net.proto - with this command you can set the network layer protocol.Supported : ipv4, ipv6, arp
Example: net.proto == arp
3.src.port,src.host,dst.port,dst.host - commands for specifying source/destination port/host
Example: src.port == 443
4.Also supported: not, !=, and, &&, or, ||, == and ()
Example: (src.port == 443 and tcp) or (dst.host 192.168.0.30 and udp)
