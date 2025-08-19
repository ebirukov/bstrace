package main

import (
	"context"
	"errors"
	"flag"
	"github.com/ebirukov/bstrace/pkg/cpio"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// QemuRunner - утилита для запуска ядра Linux в QEMU с автоматическим созданием initramfs.
//
// Примеры использования:
//
//  1. Запуск для архитектуры arm64:
//     QEMU_ARCH=arm64 go run cmd/qemu-runner/main.go -kernel kernel/arm64/linux-5.10.0-32-arm64
//
//  2. Запуск для архитектуры amd64 с кастомными параметрами:
//     QEMU_ARCH=amd64 QEMU_BIN=/usr/bin/qemu-system-amd64 \
//     go run cmd/qemu-runner/main.go -kernel kernel/amd64/linux-6.1.0-35-amd64 \
//     -rootfs build/amd64/initramfs -timeout 10s
//
// Параметры:
//
//	-kernel string    Путь к образу ядра Linux (обязательный)
//	-rootfs string    Путь к корневой файловой системе для initramfs (по умолчанию "build/$ARCH/initramfs/")
//	-timeout duration Максимальное время выполнения QEMU (по умолчанию 30s)
//
// Переменные окружения:
//
//	QEMU_ARCH    Целевая архитектура (по умолчанию GOARCH)
//	QEMU_BIN     Путь к исполняемому файлу QEMU (по умолчанию "qemu-system-$ARCH")
//	QEMU_ARGS    Дополнительные аргументы QEMU
//
// Особенности:
// - Автоматически создает временный initramfs в формате cpio
// - Поддерживает архитектуры amd64 и arm64
// - Обрабатывает таймауты и сигналы завершения
// - Автоматически очищает временные файлы
func main() {
	arch := getEnv("QEMU_ARCH", runtime.GOARCH)

	kernelPathVar := flag.String("kernel", "", "Path to linux kernel image")
	initRootFS := flag.String("rootfs", "build/"+arch+"/initramfs/", "Path to initramfs root directory")
	timeoutVar := flag.Duration("timeout", 30*time.Second, "Max time of qemu execution")

	flag.Parse()

	kernelPath := *kernelPathVar

	if _, err := os.Stat(kernelPath); os.IsNotExist(err) {
		log.Printf("kernel path does not exist: %s", kernelPath)

		flag.Usage()
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeoutVar)

	defer cancel()

	pwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("could not get current working dir: %v", err)
	}

	log.Printf("current working dir: %s", pwd)

	initrdFile, err := os.CreateTemp(pwd, "initramfs.cpio")
	if err != nil {
		log.Fatalf("could not create file initramfs.cpio: %v", err)
	}

	defer func() {
		initrdFile.Close()
		if err := os.Remove(initrdFile.Name()); err != nil {
			log.Fatalf("could not remove initramfs.cpio: %v", err)
		}
	}()

	if err := cpio.Create(initrdFile, *initRootFS); err != nil {
		log.Fatalf("could not create cpio fs %s: %v", initrdFile.Name(), err)
	}

	var argsEnv string
	switch arch {
	case "amd64":
		argsEnv = getEnv(
			"QEMU_ARGS",
			"-machine pc -nographic -no-reboot -append console=ttyS0")
	case "arm64":
		argsEnv = getEnv(
			"QEMU_ARGS",
			"-machine virt -cpu cortex-a53 -nographic -no-reboot -append console=ttyAMA0")
	default:
		log.Fatalf("unknown architecture: %s", arch)
	}

	vmArgs := strings.Split(argsEnv, " ")
	vmArgs = append(vmArgs,
		"-kernel", kernelPath,
		"-initrd", initrdFile.Name())

	defaultVal := strings.Join([]string{"qemu-system", arch}, "-")
	cmdStr := getEnv("QEMU_BIN", defaultVal)

	cmd := exec.CommandContext(ctx, cmdStr, vmArgs...)

	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr

	log.Printf("executing: %v", cmd)

	if err := cmd.Start(); err != nil {
		log.Fatalf("could not start process: %v", err)
	}

	proc := cmd.Process

	log.Printf("process %s started with pid: %d", cmdStr, proc.Pid)

	defer proc.Release()

	state, err := proc.Wait()
	if err != nil {
		log.Fatalf("could not complete process: %v; state %s", err, state)
	}

	if state.Success() {
		log.Printf("process  %d complete succesfully with code %d", proc.Pid, state.ExitCode())

		return
	}

	switch state := state.Sys().(type) {
	case syscall.WaitStatus:
		if state.Signaled() {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				log.Printf("process %d terminated by timeout", proc.Pid)
				return
			}

			log.Printf("process terminated with signal: %s", state.Signal())
			return
		}
	}

	log.Printf("process %d completed with exit code: %d", proc.Pid, state.ExitCode())
}

func getEnv(key, defaultVal string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}

	return defaultVal
}
