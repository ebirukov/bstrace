package bpf_test

import (
	"context"
	"embed"
	"encoding/binary"
	"github.com/cilium/ebpf"
	"github.com/ebirukov/bstrace/internal/strace"
	"github.com/ebirukov/bstrace/internal/testutil"
	"github.com/ebirukov/bstrace/pkg/abi"
	extbytes "github.com/ebirukov/bstrace/pkg/bytes"
	"reflect"
	"testing"
	"time"
)

//go:embed kprog/obj/**
var bpfObjFS embed.FS

// support sign 5.10
func TestSyscallTracepointLifecycle(t *testing.T) {
	const (
		SYS_BPF        = 321
		BPF_PROG_LOAD  = 6
		FAKE_ATTR_ADDR = 0xabadcafe
		FAKE_ATTR_SIZE = 123
	)

	testObjs := &strace.BpfObjs{
		SharedObjs:      &strace.SharedObjs{},
		TracepointsObjs: &strace.TracepointsObjs{},
	}
	l := strace.NewLoader(bpfObjFS)
	if err := l.LoadBpfObjects(testObjs); err != nil {
		t.Fatalf("Error loading bpf objects: %v", err)
	}

	type testCase struct {
		name             string
		syscallNr        uint64
		arg1, arg2, arg3 uint64
		retVal           int64
		expected         *SyscallInfo
	}

	tests := []testCase{
		{
			name:      "bpf_prog_load",
			syscallNr: SYS_BPF,
			arg1:      BPF_PROG_LOAD,
			arg2:      FAKE_ATTR_ADDR,
			arg3:      FAKE_ATTR_SIZE,
			retVal:    0,
			expected: &SyscallInfo{
				Nr:   SYS_BPF,
				Arg1: BPF_PROG_LOAD,
				Arg2: FAKE_ATTR_ADDR,
				Arg3: FAKE_ATTR_SIZE,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			events, err := testutil.StartWatchRingReader[SyscallInfo](ctx, testObjs.TracepointsObjs.EventBuf)
			if err != nil {
				t.Fatalf("startRingReader failed: %v", err)
			}

			argsPtr, err := abi.CreateSyscallArgs(tt.syscallNr, tt.arg1, tt.arg2, tt.arg3)
			if err != nil {
				t.Fatalf("error create syscall args: %v", err)
			}

			builder := extbytes.Builder{}

			enterCtx := builder.Reset().
				WritePointer(binary.LittleEndian, argsPtr).
				WriteUint64(binary.LittleEndian, tt.syscallNr).
				Bytes()

			if ret, err := testObjs.TracepointsObjs.SyscallEnter.Run(&ebpf.RunOptions{
				Context: enterCtx,
			}); err != nil {
				t.Fatalf("SyscallEnter failed: %v", err)
			} else if ret != 0 {
				t.Errorf("SyscallEnter returned non-zero: %d", ret)
			}

			exitCtx := builder.Reset().
				WritePointer(binary.LittleEndian, argsPtr).
				WriteInt64(binary.LittleEndian, tt.retVal).
				Bytes()

			if ret, err := testObjs.TracepointsObjs.SyscallExit.Run(&ebpf.RunOptions{
				Context: exitCtx,
			}); err != nil {
				t.Fatalf("SyscallExit failed: %v", err)
			} else if ret != 0 {
				t.Errorf("SyscallExit returned non-zero: %d", ret)
			}

			select {
			case <-ctx.Done():
				t.Fatalf("Timeout waiting for event: %v", context.Cause(ctx))
			case info := <-events:
				if info == nil {
					t.Fatal("Received nil syscall info")
				}
				if !reflect.DeepEqual(info, tt.expected) {
					t.Errorf("Unexpected syscall info:\n  got:  %+v\n  want: %+v", info, tt.expected)
				}
			case <-time.After(100 * time.Millisecond):
				t.Fatal("Timeout waiting for syscall info")
			}
		})
	}
}

type SyscallInfo struct {
	Nr   uint64
	Arg1 uint64
	Arg2 uint64
	Arg3 uint64
}
