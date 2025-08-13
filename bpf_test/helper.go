package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"unsafe"
)

type RegsX86 struct {
	R15, R14, R13, R12, Rbp, Rbx      uint64
	R11, R10, R9, R8                  uint64
	Rax, Rcx, Rdx, Rsi, Rdi           uint64
	OrigRax, Rip, Cs, Eflags, Rsp, Ss uint64
}

func AppendSyscallArgs(buf *bytes.Buffer, args ...uint64) error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("platform %s is not supported", runtime.GOARCH)
	}

	if len(args) > 6 {
		return fmt.Errorf("too many arguments %d", len(args))
	}

	regs := newRegsX86(args...)

	if err := binary.Write(buf, binary.LittleEndian, uint64(uintptr(unsafe.Pointer(&regs)))); err != nil {
		return fmt.Errorf("error write syscall arguments pointer: %w", err)
	}

	return nil
}

//go:noinline
func newRegsX86(args ...uint64) (regs RegsX86) {
	for idx, arg := range args {
		switch idx {
		case 0:
			regs.Rdi = arg
		case 1:
			regs.Rsi = arg
		case 2:
			regs.Rdx = arg
		case 3:
			regs.R10 = arg
		case 4:
			regs.R8 = arg
		case 5:
			regs.R9 = arg
		}
	}

	return
}
