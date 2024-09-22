package main

import (
	"log/slog"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	// The same default as tcpdump.
	// defaultSnapLen = 262144
	defaultSnapLen = 0
	inf            = "pflog0"
)

func main() {
	lh := slog.NewTextHandler(os.Stdout, nil)
	log := slog.New(lh)

	log.Info("capturing", "interface", inf)
	handle, err := pcap.OpenLive("pflog0", defaultSnapLen, true, pcap.BlockForever)
	if err != nil {
		log.Error("failed to capture", "interface", inf, "err", err)
		return
	}
	defer handle.Close()

	log.Info("setting filter")
	if err := handle.SetBPFFilter(""); err != nil {
		log.Error("failed to set filter", "err", err)
		return
	}

	log.Info("capturing packets")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Info("looping packets")
	for packet := range packetSource.Packets() {
		pl := packet.Layer(layers.LayerTypePFLog)
		pflogPacket := pl.(*layers.PFLog)
		spew.Dump(pflogPacket)
	}
}
