//go:build windows

package main

import (
	"io"

	"github.com/rs/zerolog"
)

func newSyslogWriter() (zerolog.LevelWriter, io.Closer, error) {
	return nil, nil, nil
}
