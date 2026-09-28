package main

import (
	"errors"
	"os"

	"github.com/straticus1/SeKretSauce/sekretsauce-cli/cmd/sekretsauce/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		var incomplete *cmd.IncompleteScanError
		if errors.As(err, &incomplete) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}
