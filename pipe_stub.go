//go:build !unix

package main

import (
	"fmt"
	"os"
)

func createPipe(_ string) (*os.File, error) {
	return nil, fmt.Errorf("named pipes are not supported on this platform")
}

func removePipe(_ string) {}
