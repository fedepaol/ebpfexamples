package main

import "C"
import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type arguments -type ssl_data_event_t uprobe bpf/uprobe.bpf.c -- -I./bpf/include

func main() {
	openSSLPath := flag.String("openssl", "/usr/bin/openssl", "Path to the OpenSSL binary")

	flag.Parse()
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := uprobeObjects{}
	if err := loadUprobeObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Open an ELF binary and read its symbols.
	ex, err := link.OpenExecutable(*openSSLPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

	up, err := ex.Uprobe("SSL_write", objs.ProbeEntrySSL_write, nil)
	if err != nil {
		log.Fatalf("creating uretprobe: %s", err)
	}
	defer up.Close()

	up1, err := ex.Uretprobe("SSL_write", objs.ProbeRetSSL_write, nil)
	if err != nil {
		log.Fatalf("creating uretprobe: %s", err)
	}
	defer up1.Close()

	rd, err := ringbuf.NewReader(objs.uprobeMaps.RingBuffer)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	var event uprobeSslDataEventT
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		fmt.Printf("got event %-64s data %-64s", event.Comm, event.Data)
	}
}
