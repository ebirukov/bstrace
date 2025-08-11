package strace

import (
	"context"
	"github.com/cilium/ebpf/link"
	"log"
)

func Run(_ context.Context) error {
	tpObjs, err := LoadBpfObjects()
	if err != nil {
		log.Fatal(err)
	}

	defer tpObjs.Close()

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
