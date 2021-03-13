# Passive-Network-Monitoring-Tool
Tool for Passive Network Monitoring

1. I have developed a tool "mydump.go" which can be used as Passive network monitoring application. It is written in Go programming language using gopacket libraries.

2. It captures traffic in Promiscuous mode which allows the network device to intercept and read each network packet.

3. Implementaion:

A. For Offline mode, the program reads the pcap file using  "pcap.OpenOffline(pcapFile)" which returns a handle. 
B. For Live mode, the program captures the network traffic using "pcap.OpenLive(device, snapshot_len, promiscuous, timeout)" which return a handle.
C. After extracting the handle, both the modes extract packetSource from gopacket.NewPacketSource(handle, handle.LinkType()) ,i.e. a library of gopacket.
D. Then it parses the packetSource for individual packet and apply required filters(pattern matching,BPFFilter) and prints the processed output.



4. Usage of mydump.go:
	sudo go run mydump.go [-i ens33] [-r "default"] [-s ""] tcp
  -i string
        a interface string (default "ens33")
  -r string
        offline file path string (default "default")
  -s string
        packet pattern string

The mentioned parameters' values are the default values.
"ens33": It is the first interface device recognized by the program which can change for different machines.
"offline.pcap": It is the pcap file where we have already dumped the network logs and packets. We are parsing this file in offline mode. By default the value is "default" for this parameter.
-s "": The default pattern is the empty string which means the program will fetch all the packets.
"tcp": This is being used as BPF Filter string.

5. Output Examples:

A. Using default parameter values:

sudo go run mydump.go

...listening on ens33
2021-03-12 19:12:25.377455 00:0c:29:85:7e:1b -> 00:50:56:ed:40:61 type 0x800 len 78
192.168.86.128:38056 -> 184.24.151.145:443(https) TCP PSH ACK
00000000  45 00 00 40 98 09 40 00  40 06 3b dc c0 a8 56 80  |E..@..@.@.;...V.|
00000010  b8 18 97 91 94 a8 01 bb  37 7e ee 94 47 44 90 47  |........7~..GD.G|
00000020  50 18 ff ff 67 05 00 00  17 03 03 00 13 da 59 2c  |P...g.........Y,|
00000030  fc 8a 80 c5 16 0b b3 ed  64 29 ae 4d 94 e0 81 7a  |........d).M...z|

B. Using different interface device (lo):

sudo go run mydump.go -i lo

...listening on lo
2021-03-12 19:15:18.900622 00:00:00:00:00:00 -> 00:00:00:00:00:00 type 0x800 len 96
127.0.0.1:50286 -> 127.0.0.53:53(domain) UDP
00000000  45 00 00 52 22 da 40 00  40 11 19 8b 7f 00 00 01  |E..R".@.@.......|
00000010  7f 00 00 35 c4 6e 00 35  00 3e fe 85 68 ab 01 00  |...5.n.5.>..h...|
00000020  00 01 00 00 00 00 00 01  06 76 6f 72 74 65 78 04  |.........vortex.|
00000030  64 61 74 61 09 6d 69 63  72 6f 73 6f 66 74 03 63  |data.microsoft.c|
00000040  6f 6d 00 00 01 00 01 00  00 29 04 00 00 00 00 00  |om.......)......|
00000050  00 00 

C. Reading the offline file(offline.pcap) with BPF filter(tcp and port 443)

sudo go run mydump.go -i ens33 -r offline.pcap tcp and port 443

2013-01-12 14:35:49.724737 c4:3d:c7:17:6f:9b -> 00:0c:29:e9:94:8e type 0x800 len 171
122.154.101.54:39437 -> 192.168.0.200:443(https) TCP PSH ACK
00000000  45 00 00 9d 6b 0f 40 00  2c 06 42 0b 7a 9a 65 36  |E...k.@.,.B.z.e6|
00000010  c0 a8 00 c8 9a 0d 01 bb  84 a0 00 fd db c2 57 d3  |..............W.|
00000020  80 18 00 2e 13 ad 00 00  01 01 08 0a 08 75 79 36  |.............uy6|
00000030  00 32 35 1a 80 67 01 03  01 00 4e 00 00 00 10 00  |.25..g....N.....|
00000040  00 39 00 00 38 00 00 35  00 00 16 00 00 13 00 00  |.9..8..5........|
00000050  0a 07 00 c0 00 00 33 00  00 32 00 00 2f 03 00 80  |......3..2../...|
00000060  00 00 05 00 00 04 01 00  80 00 00 15 00 00 12 00  |................|
00000070  00 09 06 00 40 00 00 14  00 00 11 00 00 08 00 00  |....@...........|
00000080  06 04 00 80 00 00 03 02  00 80 00 00 ff 0d 21 3b  |..............!;|
00000090  d5 b5 7b 08 01 50 0d c5  a5 c2 c1 af 38           |..{..P......8|

D. Again in offline mode, Filtering and printing the packets which contains the pattern(HTTP).

sudo go run mydump.go -i ens33 -r offline.pcap -s HTTP

2013-01-14 13:26:42.610532 c4:3d:c7:17:6f:9b -> 01:00:5e:7f:ff:fa type 0x800 len 405
192.168.0.1:1900(ssdp) -> 239.255.255.250:1900(ssdp) UDP
00000000  45 00 01 87 57 c3 00 00  01 11 af ff c0 a8 00 01  |E...W...........|
00000010  ef ff ff fa 07 6c 07 6c  01 73 1f 78 4e 4f 54 49  |.....l.l.s.xNOTI|
00000020  46 59 20 2a 20 48 54 54  50 2f 31 2e 31 0d 0a 48  |FY * HTTP/1.1..H|
00000030  6f 73 74 3a 20 32 33 39  2e 32 35 35 2e 32 35 35  |ost: 239.255.255|
00000040  2e 32 35 30 3a 31 39 30  30 0d 0a 43 61 63 68 65  |.250:1900..Cache|
00000050  2d 43 6f 6e 74 72 6f 6c  3a 20 6d 61 78 2d 61 67  |-Control: max-ag|
00000060  65 3d 36 30 0d 0a 4c 6f  63 61 74 69 6f 6e 3a 20  |e=60..Location: |
00000070  68 74 74 70 3a 2f 2f 31  39 32 2e 31 36 38 2e 30  |http://192.168.0|
00000080  2e 31 3a 31 39 30 30 2f  57 46 41 44 65 76 69 63  |.1:1900/WFADevic|
00000090  65 2e 78 6d 6c 0d 0a 4e  54 53 3a 20 73 73 64 70  |e.xml..NTS: ssdp|
000000a0  3a 61 6c 69 76 65 0d 0a  53 65 72 76 65 72 3a 20  |:alive..Server: |
000000b0  50 4f 53 49 58 2c 20 55  50 6e 50 2f 31 2e 30 20  |POSIX, UPnP/1.0 |
000000c0  42 72 6f 61 64 63 6f 6d  20 55 50 6e 50 20 53 74  |Broadcom UPnP St|
000000d0  61 63 6b 2f 65 73 74 69  6d 61 74 69 6f 6e 20 31  |ack/estimation 1|
000000e0  2e 30 30 0d 0a 4e 54 3a  20 75 72 6e 3a 73 63 68  |.00..NT: urn:sch|
000000f0  65 6d 61 73 2d 77 69 66  69 61 6c 6c 69 61 6e 63  |emas-wifiallianc|
00000100  65 2d 6f 72 67 3a 73 65  72 76 69 63 65 3a 57 46  |e-org:service:WF|
00000110  41 57 4c 41 4e 43 6f 6e  66 69 67 3a 31 0d 0a 55  |AWLANConfig:1..U|
00000120  53 4e 3a 20 75 75 69 64  3a 46 35 31 39 33 39 30  |SN: uuid:F519390|
00000130  41 2d 34 34 44 44 2d 32  39 35 38 2d 36 32 33 37  |A-44DD-2958-6237|
00000140  2d 45 41 33 37 42 39 38  37 43 33 46 44 3a 3a 75  |-EA37B987C3FD::u|
00000150  72 6e 3a 73 63 68 65 6d  61 73 2d 77 69 66 69 61  |rn:schemas-wifia|
00000160  6c 6c 69 61 6e 63 65 2d  6f 72 67 3a 73 65 72 76  |lliance-org:serv|
00000170  69 63 65 3a 57 46 41 57  4c 41 4e 43 6f 6e 66 69  |ice:WFAWLANConfi|
00000180  67 3a 31 0d 0a 0d 0a 


