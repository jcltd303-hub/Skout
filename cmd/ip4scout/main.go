package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"
	"github.com/jcltd303-hub/Skout"
	"github.com/jcltd303-hub/Skout/certificates"
	"github.com/jcltd303-hub/Skout/version"
)

var App struct {
	Random ip4scout.RandomCommand `cmd:"" help:"Scans random public IPs"`
	Certs  certificates.Command   `cmd:"" help:"Collect certificates from l9format endpoint JSON on stdin"`
}

func main() {
	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-version" {
			fmt.Printf("ip4scout %s\n", version.Version)
			return
		}
	}
	ctx := kong.Parse(&App)
	// Call the Run() method of the selected parsed command.
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
