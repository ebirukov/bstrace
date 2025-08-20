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
	log.Printf("starting process")

	binExecFile := "test"
	if len(os.Args) >= 2 {
		binExecFile = os.Args[1]
	}

	if _, err := os.Stat(binExecFile); os.IsNotExist(err) {
		log.Fatalf("exec '%s' does not exist", binExecFile)
	}

	cmd := exec.Command("/" + binExecFile)

	cmd.Stdout, cmd.Stderr, cmd.Stdin = log.Writer(), log.Writer(), os.Stdin

	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	go func() {
		if err := debug.Attach(ctx, log.Writer()); err != nil {
			log.Printf("error trace log: %v", err)
		}
	}()

	if err := cmd.Run(); err != nil {
		log.Printf("could not run process: %v", err)
	}

	log.Printf("test finished with exit code: %d", cmd.ProcessState.ExitCode())

	syscall.Sync()
	if err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
		log.Printf("could reboot os: %v", err)

		os.Exit(0)
	}

	log.Printf("shutdown process")
}
