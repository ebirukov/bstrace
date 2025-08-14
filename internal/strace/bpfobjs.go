package strace

import (
	"github.com/cilium/ebpf"
	"io"
)

type SharedObjs struct {
	SysCallDataMap *ebpf.Map `ebpf:"sc_data"`
}

func (co *SharedObjs) Close() error {
	return close(co.SysCallDataMap)
}

func (co *SharedObjs) Maps() map[string]*ebpf.Map {
	return map[string]*ebpf.Map{
		"sc_data": co.SysCallDataMap,
	}
}

type TracepointsObjs struct {
	ProgMap      *ebpf.Map     `ebpf:"sc_parsers"`
	ScDataMap    *ebpf.Map     `ebpf:"sc_data"`
	EventBuf     *ebpf.Map     `ebpf:"evt_buf"`
	SyscallEnter *ebpf.Program `ebpf:"sc_enter"`
	SyscallExit  *ebpf.Program `ebpf:"sc_exit"`
}

func (tpo *TracepointsObjs) Close() error {
	return close(
		tpo.ProgMap,
		tpo.ScDataMap,
		tpo.EventBuf,
		tpo.SyscallEnter,
		tpo.SyscallExit,
	)
}

type BpfObjs struct {
	SharedObjs      *SharedObjs
	TracepointsObjs *TracepointsObjs
}

func close(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}

	return nil
}
