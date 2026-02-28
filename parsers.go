package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type LayerParser func(packet gopacket.Packet, layer gopacket.Layer)

var parsers = map[gopacket.LayerType]LayerParser{
	layers.LayerTypeTCP: parseTCP,
	layers.LayerTypeUDP: parseUDP,
	layers.LayerTypeDNS: parseDNS,
}

func parseTCP(packet gopacket.Packet, layer gopacket.Layer) {
	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000000")
	tcp := layer.(*layers.TCP)

	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}

	srcIP, dstIP := netLayer.NetworkFlow().Src(), netLayer.NetworkFlow().Dst()
	fmt.Printf("%s [TCP] %s:%d > %s:%d\n", timestamp, srcIP, tcp.SrcPort, dstIP, tcp.DstPort)
}

func parseUDP(packet gopacket.Packet, layer gopacket.Layer) {
	if packet.ApplicationLayer() != nil {
		return
	}

	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000000")
	udp := layer.(*layers.UDP)

	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}

	srcIP, dstIP := netLayer.NetworkFlow().Src(), netLayer.NetworkFlow().Dst()
	fmt.Printf("%s [UDP] %s:%d > %s:%d\n", timestamp, srcIP, udp.SrcPort, dstIP, udp.DstPort)
}

func parseDNS(packet gopacket.Packet, layer gopacket.Layer) {
	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000000")
	dns := layer.(*layers.DNS)

	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}

	srcIP, dstIP := netLayer.NetworkFlow().Src(), netLayer.NetworkFlow().Dst()

	if !dns.QR { // QR Flag is 0 when it's a DNS query
		for _, q := range dns.Questions {
			fmt.Printf("%s [DNS] %s asked %s for '%s' (%s)\n", timestamp, srcIP, dstIP, q.Name, q.Type.String())
		}
	} else {
		if len(dns.Questions) > 0 && len(dns.Answers) == 0 {
			q := dns.Questions[0]
			fmt.Printf("%s [DNS] %s replied to '%s' (%s) with 0 answers\n", timestamp, srcIP, q.Name, q.Type.String())
			return
		}

		for _, ans := range dns.Answers {
			switch ans.Type {
			case layers.DNSTypeA, layers.DNSTypeAAAA:
				fmt.Printf("%s [DNS] %s answered with: %s\n", timestamp, srcIP, ans.IP)
			case layers.DNSTypeCNAME:
				fmt.Printf("%s [DNS] %s answered with alias: %s\n", timestamp, srcIP, ans.CNAME)
			}
		}
	}
}

func processPacket(packet gopacket.Packet) {
	for _, layer := range packet.Layers() {
		if parseFunc, exists := parsers[layer.LayerType()]; exists {
			parseFunc(packet, layer)
		}
	}
}
