//go:build unix

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"
)

func createPipe(path string) (*os.File, error) {
	err := syscall.Mkfifo(path, 0600)
	if err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return nil, fmt.Errorf("mkfifo: %w", err)
		}
		info, statErr := os.Stat(path)
		if statErr != nil {
			return nil, statErr
		}
		if info.Mode()&os.ModeNamedPipe == 0 {
			return nil, fmt.Errorf("%s exists and is not a named pipe", path)
		}
	}
	log.Printf("waiting for reader on %s...", path)
	f, err := os.OpenFile(path, os.O_WRONLY, 0) // blocks until reader connects
	if err != nil {
		return nil, fmt.Errorf("open pipe: %w", err)
	}
	return f, nil
}

func removePipe(path string) {
	os.Remove(path)
}
