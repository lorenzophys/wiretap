package main

import (
	"errors"
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
				if errors.Is(err, afpacket.ErrTimeout) {
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
}
