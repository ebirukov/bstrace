package strace

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func Trace(evtBuf *ebpf.Map) error {
	// Открываем ringbuffer для чтения событий
	rd, err := ringbuf.NewReader(evtBuf)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	log.Println("Waiting for events... Press Ctrl+C to exit")
	//u32 syscall_nr;
	//u64 sc_arg1;
	//u64 sc_arg2;
	//u64 sc_arg3;
	//union bpf_attr attr;
	//s32 syscall_ret;
	var event struct {
		SyscallNR uint32
		Arg1      uint64
		Arg2      uint64
		Arg3      uint64
	}

	// Ждем сигнала завершения
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		err := rd.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	// Обработка событий
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return nil
			}
			log.Printf("Failed to read event: %v", err)
			continue
		}

		// Парсим бинарные данные в структуру
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Failed to parse event: %v", err)
			continue
		}

		log.Printf("New process started: Syscall=%d, Arg1=%d, Arg2=%d, Arg3=%d", event.SyscallNR, event.Arg1, event.Arg2, event.Arg3)
	}
}
