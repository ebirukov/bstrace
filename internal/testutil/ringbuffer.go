package testutil

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"log"
)

func StartWatchRingReader[T any](ctx context.Context, ringBuf *ebpf.Map) (chan *T, error) {
	rd, err := ringbuf.NewReader(ringBuf)
	if err != nil {
		return nil, err
	}

	res := make(chan *T)

	go func(ctx context.Context) {
		ctx, cancel := context.WithCancelCause(ctx)

		defer func() {
			rd.Close()
			close(res)
		}()

		for {
			select {
			case <-ctx.Done():
				cancel(ctx.Err())
				return
			default:
			}
			record, err := rd.Read()
			if err != nil {
				err := fmt.Errorf("error reading ringbuf record: %w", err)
				log.Println(err)

				cancel(err)

				return
			}

			log.Printf("rec: %v", record)

			var info T
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &info); err != nil {
				err := fmt.Errorf("error parsing ringbuf event: %w", err)
				log.Println(err)

				cancel(err)

				return
			}

			select {
			case res <- &info:
			case <-ctx.Done():
				cancel(ctx.Err())

				return
			}
		}

	}(ctx)

	return res, nil
}
