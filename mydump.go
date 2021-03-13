package main

import (
	"fmt"
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"encoding/hex"
	"time"
	"log"
	"strings"
)

var (
    device       string = "default"
    snapshot_len int32  = 1024
    promiscuous  bool   = true
    err          error
    timeout      time.Duration = 30 * time.Second
    handle       *pcap.Handle
	timestamp	 string
	mac_n_etype  string
	IPv4_data 	 string
	len_packet	 int
	ip_protocol string
	bpffilter_string	string = ""
	pattern			string = ""
	
)

//To capture the timestamp of the packet
func print_timestamp(packet gopacket.Packet) {
	timestamp = packet.Metadata().Timestamp.Format("2006-01-02 15:04:05.000000")
}

// To capture the MAC addresses of the packet
func print_mac(packet gopacket.Packet){

	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
    if ethernetLayer != nil {		
        ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		etype := string(hex.Dump(packet.Data()[12:14]))
		etype = strings.ReplaceAll(etype[11:15], " ", "")
		mac_n_etype = ethernetPacket.SrcMAC.String() + " -> " +ethernetPacket.DstMAC.String()+ " type " + "0x" +  etype
	    } else {
		fmt.Println("Ethernet Layer does not found!")
	}
}

//To parse the layers and capture IPv4 related details(TCP,UDP,etc)
func print_len_ips(packet gopacket.Packet)  {

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer != nil {
        ip, _ := ipLayer.(*layers.IPv4)
		// fmt.Printfip
		ip_protocol = ip.Protocol.String()

		switch ip_protocol {
			case "TCP":			
				{
					print_tcp(packet,ip)
					break
				}
			case "UDP":
				{
					print_udp(packet,ip)
					break
				}
			case "ICMPv4":
				{
					print_icmp(packet,ip)	
					break
				}
			default:
				IPv4_data = ip.SrcIP.String()+ " -> " + ip.DstIP.String()
				IPv4_data +=  " OTHER"

		}   
	} 
}

//To capture the entire packet length : similar to tcpdump -e command
func print_length(packet gopacket.Packet)  {

	len_packet = packet.Metadata().CaptureInfo.Length
}

// To print the payload of the entire packet
func print_packet_data(packet gopacket.Packet)  {
	Data := hex.Dump(packet.Data()[14:])
	fmt.Println(Data)
}

//To capture packets details with TCP protocols

func print_tcp(packet gopacket.Packet, ip *layers.IPv4){

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		// fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)
		IPv4_data =  ip.SrcIP.String()+":"+tcp.SrcPort.String()+ " -> " + ip.DstIP.String()+":"+tcp.DstPort.String()
		IPv4_data +=  " " + ip.Protocol.String()
		if tcp.FIN {
			IPv4_data += " FIN"
		}
		if tcp.SYN {
			IPv4_data += " SYN"
		} 
		if tcp.RST {
			IPv4_data += " RST"
		}
		if tcp.PSH {
			IPv4_data += " PSH"
		}
		if tcp.ACK {
			IPv4_data += " ACK"
		}
		if tcp.URG {
			IPv4_data += " URG"
		}
		if tcp.ECE {
			IPv4_data += " ECE"
		}
		if tcp.CWR {
			IPv4_data += " CWR"
		}		
		if tcp.NS {
			IPv4_data += " NS"
		}
		return
	}
}

//To capture packets details with UDP protocol
func print_udp(packet gopacket.Packet, ip *layers.IPv4)  {	
	udpLayer := packet.Layer(layers.LayerTypeUDP)
    if udpLayer != nil {
        // fmt.Println("UDP layer detected.")
        udp, _ := udpLayer.(*layers.UDP)
		IPv4_data =  ip.SrcIP.String()+":"+ udp.SrcPort.String()+ " -> " + ip.DstIP.String()+":"+ udp.DstPort.String()
		IPv4_data +=  " " + ip.Protocol.String()
		return
    }	
}

//To capture packets details with ICMPv4 protocol
func print_icmp(packet gopacket.Packet, ip *layers.IPv4)  {	
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
    if icmpLayer != nil {
        // fmt.Println("ICMP layer detected.")
		IPv4_data =  ip.SrcIP.String()+ " -> " + ip.DstIP.String()
		IPv4_data +=  " " + ip.Protocol.String()
		return
    }	
}

// To print packets in certain format
func format_packet(packet gopacket.Packet)  {

	print_timestamp(packet)
	print_mac(packet)
	print_length(packet)	
	fmt.Println(timestamp, mac_n_etype,"len", len_packet)
	len_packet = 0
	print_len_ips(packet)
	fmt.Println(IPv4_data)
	IPv4_data = ""
	print_packet_data(packet)
	
}
// To perfrom BPF filtering
func bpffilter(handle *pcap.Handle, filter string){

    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }

}

func main() {
	dev,_ := pcap.FindAllDevs() 		
	device = dev[0].Name

	int_ptr := flag.String("i",device,"a interface string")
	file_ptr := flag.String("r","default","offline file path string")
	str_ptr := flag.String("s",pattern,"packet pattern string")
	flag.Parse()

	if len(flag.Args())>0{
		for str := range flag.Args(){
			bpffilter_string += flag.Args()[str] + " "
		}
	}

	if *file_ptr != "default"{		// Offline Mode
		pcapFile := *file_ptr
		handle, err = pcap.OpenOffline(pcapFile)
		if err != nil { log.Fatal(err) }
		defer handle.Close()

		if len(bpffilter_string)>0{
			bpffilter(handle, bpffilter_string)
		}	
		if *str_ptr != ""{
			pattern = *str_ptr
		}

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {

			applayer := packet.ApplicationLayer()
			if applayer != nil {
				if strings.Contains(string(applayer.Payload()), pattern) {
					format_packet(packet)				
				}
			}
		}
	} else {			// Online Mode

		if *int_ptr != device{
			device = *int_ptr
		} 
		handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
		if err != nil {log.Fatal(err) }
		defer handle.Close()
		print("...listening on ",device, "\n")

		if len(bpffilter_string)>0{
			bpffilter(handle, bpffilter_string)
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {

			applicationLayer := packet.ApplicationLayer()
			if applicationLayer != nil {
				if strings.Contains(string(applicationLayer.Payload()), pattern) {
					format_packet(packet)
				}
			}
			
		}			
	}

}