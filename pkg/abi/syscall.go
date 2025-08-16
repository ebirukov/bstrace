package abi

import (
	"fmt"
	"runtime"
	"unsafe"
)

type regsX86 struct {
	R15, R14, R13, R12, Rbp, Rbx      uint64
	R11, R10, R9, R8                  uint64
	Rax, Rcx, Rdx, Rsi, Rdi           uint64
	OrigRax, Rip, Cs, Eflags, Rsp, Ss uint64
}

type regsARM64 struct {
	X0, X1, X2, X3     uint64 // arg0 - arg3
	X4, X5, X6, X7     uint64 // arg4 - arg5 + extra
	X8, X9, X10, X11   uint64 // syscall number + temps
	X12, X13, X14, X15 uint64
	X16, X17, X18, X19 uint64
	X20, X21, X22, X23 uint64
	X24, X25, X26, X27 uint64
	X28, X29, X30      uint64 // X29 = FP, X30 = LR
	Sp, Pc, Pstate     uint64
}

func CreateSyscallArgs(syscallNumber uint64, args ...uint64) (unsafe.Pointer, error) {
	if len(args) > 6 {
		return nil, fmt.Errorf("too many arguments %d", len(args))
	}
	switch runtime.GOARCH {
	case "amd64":
		regs := newRegsX86(syscallNumber, args...)

		return unsafe.Pointer(&regs), nil
	case "arm64":
		regs := newRegsARM64(syscallNumber, args...)

		return unsafe.Pointer(&regs), nil
	default:
		return nil, fmt.Errorf("unsupported platform %s", runtime.GOARCH)
	}
}

func newRegsX86(syscallNumber uint64, args ...uint64) (regs regsX86) {
	regs.OrigRax = syscallNumber

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

func newRegsARM64(syscallNumber uint64, args ...uint64) (regs regsARM64) {
	regs.X8 = syscallNumber // syscall number in x8

	for idx, arg := range args {
		switch idx {
		case 0:
			regs.X0 = arg
		case 1:
			regs.X1 = arg
		case 2:
			regs.X2 = arg
		case 3:
			regs.X3 = arg
		case 4:
			regs.X4 = arg
		case 5:
			regs.X5 = arg
		}
	}

	return
}
