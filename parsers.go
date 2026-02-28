package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type LayerParser func(packet gopacket.Packet, layer gopacket.Layer)

func (app *Application) parseTCP(packet gopacket.Packet, layer gopacket.Layer) {
	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000000")
	tcp := layer.(*layers.TCP)

	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}

	srcIP, dstIP := netLayer.NetworkFlow().Src(), netLayer.NetworkFlow().Dst()
	logLine := fmt.Sprintf("%s [TCP] %s:%d > %s:%d\n", timestamp, srcIP, tcp.SrcPort, dstIP, tcp.DstPort)

	select {
	case app.logChannel <- logLine:
	default:
		// Drop the printing, too many packets
	}
}

func (app *Application) parseUDP(packet gopacket.Packet, layer gopacket.Layer) {
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
	logLine := fmt.Sprintf("%s [UDP] %s:%d > %s:%d\n", timestamp, srcIP, udp.SrcPort, dstIP, udp.DstPort)

	select {
	case app.logChannel <- logLine:
	default:
		// Drop the printing, too many packets
	}
}

func (app *Application) parseDNS(packet gopacket.Packet, layer gopacket.Layer) {
	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000000")
	dns := layer.(*layers.DNS)

	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return
	}

	srcIP, dstIP := netLayer.NetworkFlow().Src(), netLayer.NetworkFlow().Dst()

	if !dns.QR { // QR Flag is 0 when it's a DNS query
		for _, q := range dns.Questions {
			logLine := fmt.Sprintf("%s [DNS] %s asked %s for '%s' (%s)\n", timestamp, srcIP, dstIP, q.Name, q.Type.String())

			select {
			case app.logChannel <- logLine:
			default:
				// Drop the printing, too many packets
			}
		}
	} else {
		if len(dns.Questions) > 0 && len(dns.Answers) == 0 {
			q := dns.Questions[0]
			logLine := fmt.Sprintf("%s [DNS] %s replied to '%s' (%s) with 0 answers\n", timestamp, srcIP, q.Name, q.Type.String())

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
				logLine = fmt.Sprintf("%s [DNS] %s answered with: %s\n", timestamp, srcIP, ans.IP)
			case layers.DNSTypeCNAME:
				logLine = fmt.Sprintf("%s [DNS] %s answered with alias: %s\n", timestamp, srcIP, ans.CNAME)
			}

			if logLine == "" {
				select {
				case app.logChannel <- logLine:
				default:
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
