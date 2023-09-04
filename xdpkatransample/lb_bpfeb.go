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

type lbArguments struct {
	DstMac [6]uint8
	_      [2]byte
	Daddr  uint32
	Saddr  uint32
	Vip    uint32
}

// loadLb returns the embedded CollectionSpec for lb.
func loadLb() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_LbBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load lb: %w", err)
	}

	return spec, err
}

// loadLbObjects loads lb and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*lbObjects
//	*lbPrograms
//	*lbMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadLbObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadLb()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// lbSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type lbSpecs struct {
	lbProgramSpecs
	lbMapSpecs
}

// lbSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type lbProgramSpecs struct {
	XdpProgFunc *ebpf.ProgramSpec `ebpf:"xdp_prog_func"`
}

// lbMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type lbMapSpecs struct {
	XdpParamsArray *ebpf.MapSpec `ebpf:"xdp_params_array"`
}

// lbObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadLbObjects or ebpf.CollectionSpec.LoadAndAssign.
type lbObjects struct {
	lbPrograms
	lbMaps
}

func (o *lbObjects) Close() error {
	return _LbClose(
		&o.lbPrograms,
		&o.lbMaps,
	)
}

// lbMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadLbObjects or ebpf.CollectionSpec.LoadAndAssign.
type lbMaps struct {
	XdpParamsArray *ebpf.Map `ebpf:"xdp_params_array"`
}

func (m *lbMaps) Close() error {
	return _LbClose(
		m.XdpParamsArray,
	)
}

// lbPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadLbObjects or ebpf.CollectionSpec.LoadAndAssign.
type lbPrograms struct {
	XdpProgFunc *ebpf.Program `ebpf:"xdp_prog_func"`
}

func (p *lbPrograms) Close() error {
	return _LbClose(
		p.XdpProgFunc,
	)
}

func _LbClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed lb_bpfeb.o
var _LbBytes []byte
