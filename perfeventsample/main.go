// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type stack_key -type arguments perf ebpf/perf_event.c -- -I ebpf/include

func main() {
	var (
		pid int
	)

	flag.IntVar(&pid, "pid", -1, "the pid we want to filter")
	flag.Parse()

	if pid == -1 {
		log.Fatalf("invalid pid argument")
	}

	objs := perfObjects{}
	if err := loadPerfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	args := perfArguments{
		Pid: uint32(pid),
	}

	err := objs.ParamsArray.Put(uint32(0), args)
	if err != nil {
		log.Fatalf("failed to set args %v", err)
	}
	cpus, err := getCPUs()
	if err != nil {
		log.Fatalf("failed to get cpus: %v", err)
	}
	for _, cpu := range cpus {
		pe, err := newPerfEvent(int(cpu), 1)
		if err != nil {
			log.Fatalf("new perf event: %v", err)
		}
		opts := link.RawLinkOptions{
			Target:  pe.fd,
			Program: objs.DoPerfEvent,
			Attach:  ebpf.AttachPerfEvent,
		}

		pe.link, err = link.AttachRawLink(opts)
		if err != nil {
			log.Fatalf("attach raw link: %v", err)
		}
	}
	var toDump perfStackKey
	var maxCount uint32
	for i := 0; i < 10; i++ {
		time.Sleep(time.Second)
		var mapKey perfStackKey
		var count uint32
		iter := objs.Counts.Iterate()

		for iter.Next(&mapKey, &count) {
			if count > maxCount {
				maxCount = count
				toDump = mapKey
			}
		}
	}

	stack, err := objs.Stacks.LookupBytes(uint32(toDump.StackId))
	if err != nil {
		log.Fatalf("stacks lookup: %v", err)
	}
	for i := 0; i < 127; i++ {
		instructionPointerBytes := stack[i*8 : i*8+8]
		instructionPointer := binary.LittleEndian.Uint64(instructionPointerBytes)
		if instructionPointer == 0 {
			break
		}
		fmt.Println("Instruction pointer", instructionPointer)
	}
}

type perfEvent struct {
	fd   int
	link *link.RawLink
}

func newPerfEvent(cpu int, sampleRate int) (*perfEvent, error) {
	var (
		fd  int
		err error
	)
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Bits:   unix.PerfBitFreq,
		Sample: uint64(sampleRate),
	}
	fd, err = unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("open perf event: %w", err)
	}
	return &perfEvent{fd: fd}, nil
}

const cpuOnline = "/sys/devices/system/cpu/online"

// Get returns a slice with the online CPUs, for example `[0, 2, 3]`
func getCPUs() ([]uint, error) {
	buf, err := os.ReadFile(cpuOnline)
	if err != nil {
		return nil, err
	}
	return ReadCPURange(string(buf))
}

// loosely based on https://github.com/iovisor/bcc/blob/v0.3.0/src/python/bcc/utils.py#L15
func ReadCPURange(cpuRangeStr string) ([]uint, error) {
	var cpus []uint
	cpuRangeStr = strings.Trim(cpuRangeStr, "\n ")
	for _, cpuRange := range strings.Split(cpuRangeStr, ",") {
		rangeOp := strings.SplitN(cpuRange, "-", 2)
		first, err := strconv.ParseUint(rangeOp[0], 10, 32)
		if err != nil {
			return nil, err
		}
		if len(rangeOp) == 1 {
			cpus = append(cpus, uint(first))
			continue
		}
		last, err := strconv.ParseUint(rangeOp[1], 10, 32)
		if err != nil {
			return nil, err
		}
		for n := first; n <= last; n++ {
			cpus = append(cpus, uint(n))
		}
	}
	return cpus, nil
}
