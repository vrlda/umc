package main

import (
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/rs/zerolog"
)

const (
	maxLogFileSize = 10 << 20
	daemonLogFile  = "daemon.log"
)

func newDaemonLogger(dataDir, level string) (zerolog.Logger, io.Closer, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return zerolog.Logger{}, nil, err
	}

	fileWriter, err := newRotatingFileWriter(filepath.Join(dataDir, daemonLogFile), maxLogFileSize)
	if err != nil {
		return zerolog.Logger{}, nil, err
	}

	writers := []io.Writer{fileWriter}
	closers := []io.Closer{fileWriter}

	if syslogWriter, syslogCloser, err := newSyslogWriter(); err == nil && syslogWriter != nil {
		writers = append(writers, syslogWriter)
		if syslogCloser != nil {
			closers = append(closers, syslogCloser)
		}
	}

	logger := zerolog.New(zerolog.MultiLevelWriter(writers...)).
		Level(parseLogLevel(level)).
		With().
		Timestamp().
		Str("service", "openmeshd").
		Logger()

	return logger, multiCloser(closers), nil
}

func parseLogLevel(level string) zerolog.Level {
	parsed, err := zerolog.ParseLevel(level)
	if err != nil {
		return zerolog.WarnLevel
	}
	return parsed
}

type rotatingFileWriter struct {
	path    string
	maxSize int64

	mu   sync.Mutex
	file *os.File
	size int64
}

func newRotatingFileWriter(path string, maxSize int64) (*rotatingFileWriter, error) {
	writer := &rotatingFileWriter{
		path:    path,
		maxSize: maxSize,
	}
	if err := writer.open(); err != nil {
		return nil, err
	}
	return writer, nil
}

func (w *rotatingFileWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		if err := w.open(); err != nil {
			return 0, err
		}
	}

	if w.maxSize > 0 && w.size+int64(len(payload)) > w.maxSize {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}

	n, err := w.file.Write(payload)
	w.size += int64(n)
	return n, err
}

func (w *rotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	w.size = 0
	return err
}

func (w *rotatingFileWriter) open() error {
	if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
		return err
	}

	file, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}

	w.file = file
	w.size = info.Size()
	return nil
}

func (w *rotatingFileWriter) rotate() error {
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}

	rotatedPath := w.path + ".1"
	_ = os.Remove(rotatedPath)
	if err := os.Rename(w.path, rotatedPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return w.open()
}

type closerGroup []io.Closer

func (g closerGroup) Close() error {
	var closeErr error
	for _, closer := range g {
		if closer == nil {
			continue
		}
		if err := closer.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func multiCloser(closers []io.Closer) io.Closer {
	return closerGroup(closers)
}
