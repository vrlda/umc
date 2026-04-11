package main

import (
	"context"
	"fmt"
	"os"
)

func main() {
	if err := newRootCommand().ExecuteContext(context.Background()); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
