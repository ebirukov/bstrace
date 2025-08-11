package main

import (
	"context"
	"github.com/ebirukov/bstrace/internal/strace"
	"log"
)

func main() {
	if err := strace.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
