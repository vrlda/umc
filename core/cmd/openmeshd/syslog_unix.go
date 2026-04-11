//go:build !windows

package main

import (
	"io"
	"log/syslog"

	"github.com/rs/zerolog"
)

func newSyslogWriter() (zerolog.LevelWriter, io.Closer, error) {
	writer, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "openmeshd")
	if err != nil {
		return nil, nil, err
	}
	return zerolog.SyslogLevelWriter(writer), writer, nil
}
