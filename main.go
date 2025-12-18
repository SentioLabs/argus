package main

import (
	"os"

	"github.com/sentiolabs/argus/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
