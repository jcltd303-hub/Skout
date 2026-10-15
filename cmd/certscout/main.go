package main

import (
	"fmt"
	"os"

	"github.com/jcltd303-hub/Skout/certificates"
	"github.com/jcltd303-hub/Skout/version"
)

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-version" {
			fmt.Printf("certscout %s\n", version.Version)
			return
		}
	}
	os.Exit(certificates.Main(os.Args[1:]))
}
