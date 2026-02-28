package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type LayerParser func(packet gopacket.Packet, layer gopacket.Layer)

func (app *Application) parseICMPv4(packet gopacket.Packet, layer gopacket.Layer) {
	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000000")
	icmp := layer.(*layers.ICMPv4)
	icmpType := icmp.TypeCode.String()

	srcIP, dstIP, err := app.unpackNetworkLayer(packet)
	if err != nil {
		return
	}

	logLine := fmt.Sprintf("%s [ICMPv4] %s > %s type=%s id=%d seq=%d\n", timestamp, srcIP, dstIP, icmpType, icmp.Id, icmp.Seq)

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
	arp := layer.(*layers.ARP)

	srcMAC := net.HardwareAddr(arp.SourceHwAddress)

	srcIP, dstIP := net.IP(arp.SourceProtAddress).String(), net.IP(arp.DstProtAddress).String()
	if app.config.dnsResolve {
		srcIP, dstIP = app.dnsCache.getHostname(srcIP), app.dnsCache.getHostname(dstIP)
	}

	var logLine string

	switch arp.Operation {
	case layers.ARPRequest:
		logLine = fmt.Sprintf("%s [ARP] %s (%s) asks who's %s\n", timestamp, srcIP, srcMAC, dstIP)
	case layers.ARPReply:
		logLine = fmt.Sprintf("%s [ARP] %s is at %s\n", timestamp, srcIP, srcMAC)
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
	tcp := layer.(*layers.TCP)

	srcIP, dstIP, err := app.unpackNetworkLayer(packet)
	if err != nil {
		return
	}

	logLine := fmt.Sprintf("%s [TCP] %s:%d > %s:%d\n", timestamp, srcIP, tcp.SrcPort, dstIP, tcp.DstPort)

	select {
	case app.logChannel <- logLine:
		return
	default:
		return
		// Drop the printing, too many packets
	}
}

func (app *Application) parseUDP(packet gopacket.Packet, layer gopacket.Layer) {
	if packet.ApplicationLayer() != nil {
		return
	}

	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000000")
	udp := layer.(*layers.UDP)

	srcIP, dstIP, err := app.unpackNetworkLayer(packet)
	if err != nil {
		return
	}

	logLine := fmt.Sprintf("%s [UDP] %s:%d > %s:%d\n", timestamp, srcIP, udp.SrcPort, dstIP, udp.DstPort)

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
	dns := layer.(*layers.DNS)

	srcIP, dstIP, err := app.unpackNetworkLayer(packet)
	if err != nil {
		return
	}

	if !dns.QR { // QR Flag is 0 when it's a DNS query
		for _, q := range dns.Questions {
			logLine := fmt.Sprintf("%s [DNS] %s asked %s for '%s' (%s) id=%d\n", timestamp, srcIP, dstIP, q.Name, q.Type.String(), dns.ID)

			select {
			case app.logChannel <- logLine:
				return
			default:
				return
				// Drop the printing, too many packets
			}
		}
	} else {
		if len(dns.Questions) > 0 && len(dns.Answers) == 0 {
			q := dns.Questions[0]
			logLine := fmt.Sprintf("%s [DNS] %s replied to '%s' (%s) with 0 answers id=%d\n", timestamp, srcIP, q.Name, q.Type.String(), dns.ID)

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
				logLine = fmt.Sprintf("%s [DNS] %s answered with: %s id=%d\n", timestamp, srcIP, ans.IP, dns.ID)
			case layers.DNSTypeCNAME:
				logLine = fmt.Sprintf("%s [DNS] %s answered with alias: %s id=%d\n", timestamp, srcIP, ans.CNAME, dns.ID)
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
