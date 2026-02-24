package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

const (
	ifaceName string = "wlan0"
)

func main() {
	_, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("could not get '%s' interface: %v", ifaceName, err)
	}

	frameSize := 4096
	blockSize := frameSize * 128
	blockTimeout := 1 * time.Millisecond
	numBocks := 64
	poolTimeout := 50 * time.Microsecond

	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(ifaceName),
		afpacket.OptFrameSize(frameSize),
		afpacket.OptBlockSize(blockSize),
		afpacket.OptBlockTimeout(blockTimeout),
		afpacket.OptNumBlocks(numBocks),
		afpacket.OptPollTimeout(poolTimeout),
	)
	if err != nil {
		log.Fatalf("failed to create a new tpacket: %v", err)
	}
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	source.DecodeOptions = gopacket.Lazy

	for packet := range source.Packets() {
		timestamp := packet.Metadata().Timestamp

		var srcIp, dstIp, proto string
		var srcPort, dstPort uint16

		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip := ipLayer.(*layers.IPv4)
			srcIp, dstIp = ip.SrcIP.String(), ip.DstIP.String()
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			srcPort, dstPort = uint16(tcp.SrcPort), uint16(tcp.DstPort)
			proto = "TCP"
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			srcPort, dstPort = uint16(udp.SrcPort), uint16(udp.DstPort)
			proto = "UDP"
		} else if packet.Layer(layers.LayerTypeICMPv4) != nil {
			proto = "ICMP"
		} else {
			fmt.Printf("Unknown packet\n")
			continue
		}

		fmt.Printf("%s %s:%d > %s:%d %s\n",
			timestamp.Format("12:01:05.000000"),
			srcIp, srcPort,
			dstIp, dstPort,
			proto,
		)
	}
}
