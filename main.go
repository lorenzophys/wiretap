package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
)

const (
	ifaceName      string = "wlan0"
	ErrPollTimeout string = "packet poll timeout expired"
)

func main() {
	_, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("could not get '%s' interface: %v", ifaceName, err)
	}

	frameSize := 4096
	blockSize := frameSize * 128
	blockTimeout := 1 * time.Millisecond
	numBlocks := 64
	pollTimeout := 50 * time.Millisecond

	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(ifaceName),
		afpacket.OptFrameSize(frameSize),
		afpacket.OptBlockSize(blockSize),
		afpacket.OptBlockTimeout(blockTimeout),
		afpacket.OptNumBlocks(numBlocks),
		afpacket.OptPollTimeout(pollTimeout),
	)
	if err != nil {
		log.Fatalf("failed to create a new tpacket: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	source := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	source.DecodeOptions = gopacket.Lazy

	for {
		select {
		default:
			packet, err := source.NextPacket()
			if err != nil {
				if err.Error() == ErrPollTimeout {
					continue
				}
				continue
			}

			processPacket(packet)

		case <-sigCh:
			handle.Close()
			fmt.Println("Received stop signal, shutting down...")

			return
		}
	}

	// for packet := range source.Packets() {

	// 	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
	// 		ip := ipLayer.(*layers.IPv4)
	// 		srcIP, dstIP := ip.SrcIP.String(), ip.DstIP.String()
	// 	}

	// 	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
	// 		tcp := tcpLayer.(*layers.TCP)
	// 		srcPort, dstPort := uint16(tcp.SrcPort), uint16(tcp.DstPort)
	// 		fmt.Printf("%s %s:%d > %s:%d TCP\n", timestamp, srcIP, srcPort, dstIP, dstPort)
	// 		continue
	// 	}

	// 	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
	// 		udp := udpLayer.(*layers.UDP)
	// 		srcPort, dstPort := uint16(udp.SrcPort), uint16(udp.DstPort)
	// 		fmt.Printf("%s %s:%d > %s:%d UDP\n", timestamp, srcIP, srcPort, dstIP, dstPort)

	// 		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
	// 			dns := dnsLayer.(*layers.DNS)
	// 			for _, q := range dns.Questions {
	// 				fmt.Printf("    DNS query:  %s (%v)\n", q.Name, q.Type)
	// 			}
	// 			for _, a := range dns.Answers {
	// 				fmt.Printf("    DNS answer: %s -> %s\n", a.Name, a.IP)
	// 			}
	// 		}
	// 		continue
	// 	}

	// 	if packet.Layer(layers.LayerTypeICMPv4) != nil {
	// 		fmt.Printf("%s %s > %s ICMP\n", timestamp, srcIP, dstIP)
	// 		continue
	// 	}

	// 	if arpL := packet.Layer(layers.LayerTypeARP); arpL != nil {
	// 		arp := arpL.(*layers.ARP)
	// 		fmt.Printf("%s ARP %v asks for %v\n", timestamp, net.IP(arp.SourceProtAddress), net.IP(arp.DstProtAddress))
	// 		continue
	// 	}
	// }
}
