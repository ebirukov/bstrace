package bpf_test

import (
	"bytes"
	"embed"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	bpf "github.com/ebirukov/bstrace/bpf_test"
	"github.com/ebirukov/bstrace/internal/strace"
	"log"
	"reflect"
	"testing"
	"unsafe"
)

//go:embed kprog/obj/**
var bpfObjFS embed.FS

// support sign 5.10
func TestProgramRunRawTracepoint(t *testing.T) {
	testObjs := &strace.TracepointsObjs{}
	l := strace.NewLoader(bpfObjFS)
	err := l.LoadBpfObjects(testObjs)
	if err != nil {
		log.Fatalf("Error loading bpf objects: %v", err)
	}

	if err := l.LoadParsers(testObjs.ProgMap, testObjs.ScDataMap); err != nil {
		log.Fatalf("Error loading parsers: %v", err)
	}

	rd, err := ringbuf.NewReader(testObjs.EventBuf)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	const (
		SYS_BPF        = 321
		BPF_PROG_LOAD  = 6
		FAKE_ATTR_ADDR = 0xabadcafe
		FAKE_ATTR_SIZE = 123
	)

	var ctxBuf bytes.Buffer
	if err := bpf.AppendSyscallArgs(&ctxBuf, BPF_PROG_LOAD, FAKE_ATTR_ADDR, FAKE_ATTR_SIZE); err != nil {
		t.Fatal(fmt.Errorf("error write syscall args: %w", err))
	}

	if err := binary.Write(&ctxBuf, binary.LittleEndian, uint64(SYS_BPF)); err != nil { // SYS_bpf
		t.Fatal("error write argument syscall_nr:", err)
	}

	// Запускаем программу прикрепляемую raw_tp/sys_enter
	ret, err := testObjs.SyscallEnter.Run(&ebpf.RunOptions{
		Context: ctxBuf.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}

	if ret != 0 {
		t.Error("Expected return value to be 0, got", ret)
	}

	regsPtr := uintptr(unsafe.Pointer(&bpf.RegsX86{
		OrigRax: SYS_BPF, // этот syscall будет отфильтрован в BPF-программе
	}))

	ctxBuf.Truncate(0)
	if err := binary.Write(&ctxBuf, binary.LittleEndian, uint64(regsPtr)); err != nil {
		t.Fatal("write ptr:", err)
	}

	retVal := int64(0)

	if err := binary.Write(&ctxBuf, binary.LittleEndian, uint64(retVal)); err != nil {
		t.Fatal("write retval:", err)
	}

	// Запускаем программу прикрепляемую raw_tp/sys_exit
	ret, err = testObjs.SyscallExit.Run(&ebpf.RunOptions{
		Context: ctxBuf.Bytes(),
	})
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	if ret != 0 {
		t.Errorf("expected return 0, got %d", ret)
	}

	record, err := rd.Read()
	if err != nil {
		t.Errorf("Error reading record: %v", err)
	}

	info := SyscallInfo{}
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &info); err != nil {
		log.Printf("parsing ringbuf event: %s", err)
	}

	if !reflect.DeepEqual(info, SyscallInfo{
		Nr:   SYS_BPF,
		Arg1: BPF_PROG_LOAD,
		Arg2: FAKE_ATTR_ADDR,
		Arg3: FAKE_ATTR_SIZE,
	}) {
		t.Errorf("Unexpected SyscallInfo: %v", info)
	}
}

type SyscallInfo struct {
	Nr   uint64
	Arg1 uint64
	Arg2 uint64
	Arg3 uint64
}
