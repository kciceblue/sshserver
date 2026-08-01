package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/kciceblue/sshserver/runtime/internal/cli"
)

func main() {
	syscall.Umask(0o077)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(cli.Runner{Stdout: os.Stdout, Stderr: os.Stderr}.Run(ctx, os.Args[1:]))
}
