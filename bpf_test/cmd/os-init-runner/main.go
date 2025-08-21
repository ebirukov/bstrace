package main

import (
	"context"
	"github.com/ebirukov/bstrace/pkg/debug"
	"log"
	"os"
	"os/exec"
	"syscall"
)

func main() {
	log.SetPrefix("[init-daemon] ")

	defer func() {
		syscall.Sync()
		log.Printf("shutdown init process")
		if err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
			log.Printf("could reboot os: %v", err)

			os.Exit(0)
		}
	}()

	if os.Getpid() != 1 {
		log.Fatalf("must be run as os init; current pid is %d", os.Getpid())
	}

	if mkErr := os.MkdirAll("/proc", 0755); mkErr != nil {
		log.Fatalf("failed to make procfs dir %v", mkErr)
	}

	if err := syscall.Mount("proc", "proc", "proc", 0, ""); err != nil {
		log.Fatalf("failed to mount procfs: %v", err)
	}

	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		log.Fatalf("failed to open /proc/cmdline: %v", err)
	}

	log.Printf("kernel was started with non default params: %s", cmdline)

	binExecFile := "test"
	if len(os.Args) >= 2 {
		binExecFile = os.Args[1]
	}

	if _, err := os.Stat(binExecFile); os.IsNotExist(err) {
		log.Fatalf("exec '%s' does not exist", binExecFile)
	}

	cmd := exec.Command("/" + binExecFile)

	cmdLogger := log.New(log.Writer(), "["+binExecFile+"] ", log.LstdFlags)
	pw := &PrefixWriter{cmdLogger}

	cmd.Stdout, cmd.Stderr, cmd.Stdin = pw, pw, os.Stdin

	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	go func() {
		cmdLogger := log.New(log.Writer(), "tracepipe: ", log.LstdFlags)
		pw := &PrefixWriter{cmdLogger}

		if err := debug.Attach(ctx, pw); err != nil {
			log.Printf("error trace log: %v", err)

			return
		}

	}()

	if err := cmd.Run(); err != nil {
		log.Printf("could not run process: %v", err)
	}

	log.Printf("test finished with exit code: %d", cmd.ProcessState.ExitCode())
}

type PrefixWriter struct {
	logger *log.Logger
}

func (pw *PrefixWriter) Write(p []byte) (n int, err error) {
	pw.logger.Print(string(p))
	return len(p), nil
}
