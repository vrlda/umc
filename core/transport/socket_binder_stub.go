//go:build !darwin

package transport

import "syscall"

func applySocketBinding(_ string, _ string, _ syscall.RawConn, _ string, _ int) error {
	return nil
}
