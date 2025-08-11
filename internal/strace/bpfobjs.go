package strace

import (
	"github.com/cilium/ebpf"
	"io"
)

type CommonObjs struct {
	ParserProgramArray *ebpf.Map `ebpf:"progs"`
}

func (co *CommonObjs) Close() error {
	return close(co.ParserProgramArray)
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

func close(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}

	return nil
}
