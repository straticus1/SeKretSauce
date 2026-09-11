package main

import (
	"errors"
	"os"

	"github.com/afterdarktech/sekretsauce/cmd/sekretsauce/cmd"
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
