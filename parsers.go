package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type LayerParser func(packet gopacket.Packet, layer gopacket.Layer)

var parsers = map[gopacket.LayerType]LayerParser{
	layers.LayerTypeTCP: parseTCP,
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

func processPacket(packet gopacket.Packet) {
	for _, layer := range packet.Layers() {
		if parseFunc, exists := parsers[layer.LayerType()]; exists {
			parseFunc(packet, layer)
		}
	}
}
