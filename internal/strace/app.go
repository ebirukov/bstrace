package strace

import (
	"context"
	"github.com/cilium/ebpf/link"
	"github.com/ebirukov/bstrace"
	"log"
)

func Run(_ context.Context) error {
	bpfObjs := &BpfObjs{
		SharedObjs:      &SharedObjs{},
		TracepointsObjs: &TracepointsObjs{},
	}

	l := NewLoader(bstrace.BpfObjFS)

	defer bpfObjs.SharedObjs.Close()
	defer bpfObjs.TracepointsObjs.Close()

	err := l.LoadBpfObjects(bpfObjs)
	if err != nil {
		log.Fatal(err)
	}

	lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: bpfObjs.TracepointsObjs.SyscallExit,
	})
	if err != nil {
		log.Fatalf("failed to attach raw tracepoint: %v", err)
	}

	defer lnk.Close()

	lnk, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: bpfObjs.TracepointsObjs.SyscallEnter,
	})
	if err != nil {
		log.Fatalf("failed to attach raw tracepoint: %v", err)
	}

	defer lnk.Close()

	if err := Trace(bpfObjs.TracepointsObjs.EventBuf); err != nil {
		return err
	}

	return nil
}
