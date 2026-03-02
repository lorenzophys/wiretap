package main

import (
	"bufio"
	"errors"
	"flag"
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

type Config struct {
	dnsResolve bool
	ifaceName  string
}

type Application struct {
	config     Config
	dnsCache   DNSCache
	logChannel chan string
}

func main() {
	ifaceName := flag.String("i", "any", "The network interface to attach to")
	dnsResolve := flag.Bool("r", true, "Enable DNS resolution")
	flag.Parse()

	frameSize := 4096
	blockSize := frameSize * 128
	blockTimeout := 1 * time.Millisecond
	numBlocks := 64
	pollTimeout := 50 * time.Millisecond

	optInterface := afpacket.OptInterface("")
	if *ifaceName != "any" {
		_, err := net.InterfaceByName(*ifaceName)
		if err != nil {
			log.Fatalf("could not get '%s' interface: %v", *ifaceName, err)
		}

		optInterface = afpacket.OptInterface(*ifaceName)
	}

	handle, err := afpacket.NewTPacket(
		optInterface,
		afpacket.OptFrameSize(frameSize),
		afpacket.OptBlockSize(blockSize),
		afpacket.OptBlockTimeout(blockTimeout),
		afpacket.OptNumBlocks(numBlocks),
		afpacket.OptPollTimeout(pollTimeout),
	)
	if err != nil {
		log.Fatalf("failed to create a new tpacket: %v", err)
	}

	logCh := make(chan string, 10000)

	go func() {
		writer := bufio.NewWriterSize(os.Stdout, 65536)

		for logLine := range logCh {
			writer.WriteString(logLine)

			if len(logCh) == 0 {
				writer.Flush()
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	source := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	source.DecodeOptions = gopacket.Lazy

	app := &Application{
		config: Config{
			dnsResolve: *dnsResolve,
		},
		logChannel: logCh,
		dnsCache: DNSCache{
			cache: make(map[string]string),
		},
	}

	var parsers = map[gopacket.LayerType]LayerParser{
		layers.LayerTypeEthernet: app.parseEthernet,
		layers.LayerTypeICMPv4:   app.parseICMPv4,
		layers.LayerTypeIGMP:     app.parseIGMP,
		layers.LayerTypeARP:      app.parseARP,
		layers.LayerTypeTCP:      app.parseTCP,
		layers.LayerTypeUDP:      app.parseUDP,
		layers.LayerTypeDNS:      app.parseDNS,
	}

	for {
		select {
		default:
			packet, err := source.NextPacket()
			if err != nil {
				if errors.Is(err, afpacket.ErrTimeout) {
					continue
				}
				break
			}

			app.processPacket(packet, parsers)

		case <-sigCh:
			handle.Close()
			fmt.Println("Received stop signal, shutting down...")

			return
		}
	}
}
