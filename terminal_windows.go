//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

func enableTerminalStatus() {
	handle := windows.Handle(os.Stderr.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return
	}
	windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}
