package strace

import (
	"context"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/ebirukov/bstrace"
	"log"
)

func Run(_ context.Context) error {
	tpObjs := &TracepointsObjs{}
	l := NewLoader(bstrace.BpfObjFS)
	err := l.LoadBpfObjects(tpObjs)
	if err != nil {
		log.Fatal(err)
	}

	defer tpObjs.Close()

	if err := l.LoadParsers(tpObjs.ProgMap, tpObjs.ScDataMap); err != nil {
		return fmt.Errorf("error loading ebpf parser programs: %w", err)
	}

	lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: tpObjs.SyscallExit,
	})
	if err != nil {
		log.Fatalf("failed to attach raw tracepoint: %v", err)
	}

	defer lnk.Close()

	lnk, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: tpObjs.SyscallEnter,
	})
	if err != nil {
		log.Fatalf("failed to attach raw tracepoint: %v", err)
	}

	defer lnk.Close()

	if err := Trace(tpObjs.EventBuf); err != nil {
		return err
	}

	return nil
}
