package main

import (
	"fmt"
	"os"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

const prefix = "[sssh] "

func logInfo(format string, args ...any) {
	fmt.Fprintf(os.Stderr, colorCyan+prefix+colorReset+format+"\n", args...)
}

func logSuccess(format string, args ...any) {
	fmt.Fprintf(os.Stderr, colorGreen+prefix+colorReset+format+"\n", args...)
}

func logWarn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, colorYellow+prefix+colorReset+format+"\n", args...)
}

func logError(format string, args ...any) {
	fmt.Fprintf(os.Stderr, colorRed+prefix+colorReset+format+"\n", args...)
}

func logDebug(format string, args ...any) {
	if debugMode {
		fmt.Fprintf(os.Stderr, colorGray+prefix+colorReset+format+"\n", args...)
	}
}
