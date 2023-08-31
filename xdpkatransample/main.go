// This program demonstrates attaching an eBPF program to a network interface
// with XDP (eXpress Data Path). The program parses the IPv4 source address
// from packets and writes the packet count by IP to an LRU hash map.
// The userspace program (Go code in this file) prints the contents
// of the map to stdout every second.
// It is possible to modify the XDP program to drop or redirect packets
// as well -- give it a try!
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/PraserX/ipconv"
	"github.com/cilium/ebpf/link"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type arguments lb ebpf/xdp_lb.c -- -I ebpf/include

func main() {
	var (
		dstMac     string
		endpointIP string
		attachTo   string
		myIP       string
		vip        string
	)

	flag.StringVar(&dstMac, "dest-mac", "", "the mac address of the next hop")
	flag.StringVar(&endpointIP, "endpoint", "", "the ip of the endpoint")
	flag.StringVar(&myIP, "my-ip", "", "the ip of the lb")
	flag.StringVar(&attachTo, "attach-to", "", "the interface to attach this program to")
	flag.StringVar(&vip, "vip", "", "the virtual ip")

	flag.Parse()

	iface, err := net.InterfaceByName(attachTo)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", attachTo, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := lbObjects{}
	if err := loadLbObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	mac, err := macToBytes(dstMac)
	if err != nil {
		fmt.Printf("failed to convert %s to bytes", dstMac)
		panic(err)
	}
	var macArray [6]uint8
	copy(macArray[:], mac)
	intDest, err := ipconv.IPv4ToInt(net.ParseIP(endpointIP))
	if err != nil {
		panic(err)
	}
	intSrc, err := ipconv.IPv4ToInt(net.ParseIP(myIP))
	if err != nil {
		panic(err)
	}
	intVip, err := ipconv.IPv4ToInt(net.ParseIP(vip))
	if err != nil {
		panic(err)
	}
	fmt.Println("vip user", intVip)

	objs.XdpParamsArray.Put(0, lbArguments{
		Daddr:  intDest,
		Saddr:  intSrc,
		DstMac: macArray,
		Vip:    intVip,
	})
	select {}
}

func macToBytes(mac string) ([]uint8, error) {
	mac = strings.Replace(mac, ":", "", -1)

	// Parse the MAC address string into a hardware address
	macAddr, err := net.ParseMAC(mac)
	if err != nil {
		return nil, fmt.Errorf("error parsing MAC address: %w", err)
	}

	// Convert the hardware address to an array of bytes
	macBytes := macAddr[:]
	return macBytes, nil
}
