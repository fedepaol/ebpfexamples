// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type perfArguments struct{ Pid uint32 }

type perfStackKey struct {
	Pid     uint32
	_       [4]byte
	StackId int64
	Comm    [16]int8
}

// loadPerf returns the embedded CollectionSpec for perf.
func loadPerf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_PerfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load perf: %w", err)
	}

	return spec, err
}

// loadPerfObjects loads perf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*perfObjects
//	*perfPrograms
//	*perfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadPerfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadPerf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// perfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type perfSpecs struct {
	perfProgramSpecs
	perfMapSpecs
}

// perfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type perfProgramSpecs struct {
	DoPerfEvent *ebpf.ProgramSpec `ebpf:"do_perf_event"`
}

// perfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type perfMapSpecs struct {
	Counts      *ebpf.MapSpec `ebpf:"counts"`
	ParamsArray *ebpf.MapSpec `ebpf:"params_array"`
	Stacks      *ebpf.MapSpec `ebpf:"stacks"`
}

// perfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadPerfObjects or ebpf.CollectionSpec.LoadAndAssign.
type perfObjects struct {
	perfPrograms
	perfMaps
}

func (o *perfObjects) Close() error {
	return _PerfClose(
		&o.perfPrograms,
		&o.perfMaps,
	)
}

// perfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadPerfObjects or ebpf.CollectionSpec.LoadAndAssign.
type perfMaps struct {
	Counts      *ebpf.Map `ebpf:"counts"`
	ParamsArray *ebpf.Map `ebpf:"params_array"`
	Stacks      *ebpf.Map `ebpf:"stacks"`
}

func (m *perfMaps) Close() error {
	return _PerfClose(
		m.Counts,
		m.ParamsArray,
		m.Stacks,
	)
}

// perfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadPerfObjects or ebpf.CollectionSpec.LoadAndAssign.
type perfPrograms struct {
	DoPerfEvent *ebpf.Program `ebpf:"do_perf_event"`
}

func (p *perfPrograms) Close() error {
	return _PerfClose(
		p.DoPerfEvent,
	)
}

func _PerfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed perf_bpfeb.o
var _PerfBytes []byte
