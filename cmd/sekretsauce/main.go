package main

import (
	"os"

	"github.com/afterdarktech/sekretsauce/cmd/sekretsauce/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
