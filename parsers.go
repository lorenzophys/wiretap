package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type LayerParser func(packet gopacket.Packet, layer gopacket.Layer)

func (app *Application) parseEthernet(packet gopacket.Packet, layer gopacket.Layer) {
	ifaceName := getIfaceName(packet)

	eth := layer.(*layers.Ethernet)

	switch eth.EthernetType {
	case layers.EthernetTypeARP, layers.EthernetTypeIPv4, layers.EthernetTypeIPv6:
		return
	default:
		timestamp := packet.Metadata().Timestamp.Format("15:04:05.000000")

		srcMAC := eth.SrcMAC.String()
		dstMAC := eth.DstMAC.String()

		logLine := fmt.Sprintf("%s %s [ETH] %s > %s ethertype 0x%04x (%s) length %d\n",
			timestamp, ifaceName, srcMAC, dstMAC, uint16(eth.EthernetType), eth.EthernetType, len(packet.Data()),
		)

		select {
		case app.logChannel <- logLine:
			return
		default:
			return
			// Drop if terminal is lagging
		}
	}
}

func (app *Application) parseICMPv4(packet gopacket.Packet, layer gopacket.Layer) {
	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000000")
	ifaceName := getIfaceName(packet)

	icmp := layer.(*layers.ICMPv4)
	icmpType := icmp.TypeCode.String()

	srcIP, dstIP, err := app.unpackNetworkLayer(packet)
	if err != nil {
		return
	}

	logLine := fmt.Sprintf("%s %s [ICMPv4] %s > %s type %s id %d seq %d length %d\n",
		timestamp, ifaceName, srcIP, dstIP, icmpType, icmp.Id, icmp.Seq, len(packet.Data()),
	)

	select {
	case app.logChannel <- logLine:
		return
	default:
		return
		// Drop the printing, too many packets
	}
}

func (app *Application) parseIGMP(packet gopacket.Packet, layer gopacket.Layer) {
	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000000")
	ifaceName := getIfaceName(packet)

	igmp := layer.(*layers.IGMPv1or2)

	srcIP, dstIP, err := app.unpackNetworkLayer(packet)
	if err != nil {
		return
	}

	logLine := fmt.Sprintf("%s %s [IGMP] %s > %s type %s group %s length %d\n",
		timestamp, ifaceName, srcIP, dstIP, igmp.Type, igmp.GroupAddress, len(packet.Data()),
	)

	select {
	case app.logChannel <- logLine:
		return
	default:
		return
		// Drop the printing, too many packets
	}
}

func (app *Application) parseARP(packet gopacket.Packet, layer gopacket.Layer) {
	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000000")
	ifaceName := getIfaceName(packet)

	arp := layer.(*layers.ARP)

	srcMAC := net.HardwareAddr(arp.SourceHwAddress)

	srcIP, dstIP := net.IP(arp.SourceProtAddress).String(), net.IP(arp.DstProtAddress).String()
	if app.config.dnsResolve {
		srcIP, dstIP = app.dnsCache.getHostname(srcIP), app.dnsCache.getHostname(dstIP)
	}

	var logLine string

	switch arp.Operation {
	case layers.ARPRequest:
		logLine = fmt.Sprintf("%s %s [ARP] %s (%s) asks who's %s\n", timestamp, ifaceName, srcIP, srcMAC, dstIP)
	case layers.ARPReply:
		logLine = fmt.Sprintf("%s %s [ARP] %s is at %s\n", timestamp, ifaceName, srcIP, srcMAC)
	}

	select {
	case app.logChannel <- logLine:
		return
	default:
		return
		// Drop the printing, too many packets
	}
}

func (app *Application) parseTCP(packet gopacket.Packet, layer gopacket.Layer) {
	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000000")
	ifaceName := getIfaceName(packet)

	tcp := layer.(*layers.TCP)

	srcIP, dstIP, err := app.unpackNetworkLayer(packet)
	if err != nil {
		return
	}

	logLine := fmt.Sprintf("%s %s [TCP] %s:%d > %s:%d length %d\n",
		timestamp, ifaceName, srcIP, tcp.SrcPort, dstIP, tcp.DstPort, len(packet.Data()),
	)

	select {
	case app.logChannel <- logLine:
		return
	default:
		return
		// Drop the printing, too many packets
	}
}

func (app *Application) parseUDP(packet gopacket.Packet, layer gopacket.Layer) {
	if packet.Layer(layers.LayerTypeDNS) != nil {
		return
	}

	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000000")
	ifaceName := getIfaceName(packet)

	udp := layer.(*layers.UDP)

	srcIP, dstIP, err := app.unpackNetworkLayer(packet)
	if err != nil {
		return
	}

	logLine := fmt.Sprintf("%s %s [UDP] %s:%d > %s:%d length %d\n",
		timestamp, ifaceName, srcIP, udp.SrcPort, dstIP, udp.DstPort, len(packet.Data()),
	)

	select {
	case app.logChannel <- logLine:
		return
	default:
		return
		// Drop the printing, too many packets
	}
}

func (app *Application) parseDNS(packet gopacket.Packet, layer gopacket.Layer) {
	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000000")
	ifaceName := getIfaceName(packet)

	dns := layer.(*layers.DNS)

	srcIP, dstIP, err := app.unpackNetworkLayer(packet)
	if err != nil {
		return
	}

	if !dns.QR { // QR Flag is 0 when it's a DNS query
		for _, q := range dns.Questions {
			logLine := fmt.Sprintf("%s %s [DNS] %s asked %s for '%s' (%s) id=%d\n",
				timestamp, ifaceName, srcIP, dstIP, q.Name, q.Type.String(), dns.ID,
			)

			select {
			case app.logChannel <- logLine:
				return
			default:
				return
				// Drop the printing, too many packets
			}
		}
	} else {
		if dns.ResponseCode != layers.DNSResponseCodeNoErr {
			var qName string
			if len(dns.Questions) > 0 {
				qName = string(dns.Questions[0].Name)
			}

			logLine := fmt.Sprintf("%s %s [DNS] %s replied %s for '%s' id=%d\n",
				timestamp, ifaceName, srcIP, dns.ResponseCode.String(), qName, dns.ID,
			)

			select {
			case app.logChannel <- logLine:
				return
			default:
				return
			}
		}

		if len(dns.Questions) > 0 && len(dns.Answers) == 0 {
			q := dns.Questions[0]
			logLine := fmt.Sprintf("%s %s [DNS] %s replied to '%s' (%s) with 0 answers id=%d\n",
				timestamp, ifaceName, srcIP, q.Name, q.Type.String(), dns.ID,
			)

			select {
			case app.logChannel <- logLine:
				return
			default:
				return
				// Drop the printing, too many packets
			}
		}

		for _, ans := range dns.Answers {
			var logLine string
			switch ans.Type {
			case layers.DNSTypeA, layers.DNSTypeAAAA:
				logLine = fmt.Sprintf("%s %s [DNS] %s answered with: %s id=%d\n",
					timestamp, ifaceName, srcIP, ans.IP, dns.ID,
				)
			case layers.DNSTypeCNAME:
				logLine = fmt.Sprintf("%s %s [DNS] %s answered with alias: %s id=%d\n",
					timestamp, ifaceName, srcIP, ans.CNAME, dns.ID,
				)
			}

			if logLine != "" {
				select {
				case app.logChannel <- logLine:
					return
				default:
					return
					// Drop the printing, too many packets
				}
			}

		}
	}
}

func (app *Application) processPacket(packet gopacket.Packet, parsers map[gopacket.LayerType]LayerParser) {
	for _, layer := range packet.Layers() {
		if parseFunc, exists := parsers[layer.LayerType()]; exists {
			parseFunc(packet, layer)
		}
	}
}

func (app *Application) unpackNetworkLayer(packet gopacket.Packet) (string, string, error) {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return "", "", errors.New("network layer not found")
	}

	srcIP, dstIP := netLayer.NetworkFlow().Src().String(), netLayer.NetworkFlow().Dst().String()
	if app.config.dnsResolve {
		srcIP, dstIP = app.dnsCache.getHostname(srcIP), app.dnsCache.getHostname(dstIP)
	}

	return srcIP, dstIP, nil
}

func getIfaceName(packet gopacket.Packet) string {
	ifaceIdx := packet.Metadata().InterfaceIndex
	ifaceName, _ := net.InterfaceByIndex(ifaceIdx)

	return ifaceName.Name
}
