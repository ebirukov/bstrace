package debug

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	tracePipe    = "/sys/kernel/debug/tracing/trace_pipe"
	debugFSPath  = "/sys/kernel/debug"
	FSType       = "debugfs"
	FSName       = FSType
	retryTimeout = 100 * time.Millisecond
)

func initTracePipe() error {
	if _, err := os.Stat(tracePipe); os.IsNotExist(err) {
		if mkErr := os.MkdirAll(debugFSPath, 0755); mkErr != nil {
			return fmt.Errorf("failed to make debug fs dir %w", mkErr)
		}

		if err := syscall.Mount(FSName, debugFSPath, FSType, 0, ""); err != nil {
			return fmt.Errorf("failed to mount debugfs: %w", err)
		}
	}

	return nil
}

func Attach(ctx context.Context, out io.Writer) error {
	if err := initTracePipe(); err != nil {
		return err
	}

	f, err := os.Open(tracePipe)
	if err != nil {
		return fmt.Errorf("error opening trace pipe: %w", err)
	}

	pipe := bufio.NewReader(f)

	go func() {
		defer f.Close()

		<-ctx.Done()
	}()

	for {
		line, err := pipe.ReadString('\n')
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				log.Printf("trace pipe reader was closed")

				return nil
			}

			log.Printf("error read from trace pipe: %v", err)
			time.Sleep(retryTimeout)

			continue
		}

		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		if _, err = out.Write([]byte(line)); err != nil {
			if errors.Is(err, os.ErrClosed) {
				log.Printf("trace pipe writer was closed")

				return nil
			}

			return fmt.Errorf("error write trace: %v", err)
		}
	}
}
