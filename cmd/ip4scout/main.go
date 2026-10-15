package main

import (
	"github.com/LeakIX/ip4scout"
	"github.com/LeakIX/ip4scout/certificates"
	"github.com/alecthomas/kong"
)

var App struct {
	Random ip4scout.RandomCommand `cmd:"" help:"Scans random public IPs"`
	Certs  certificates.Command   `cmd:"" help:"Collect certificates from l9format endpoint JSON on stdin"`
}

func main() {
	ctx := kong.Parse(&App)
	// Call the Run() method of the selected parsed command.
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
