package main

import (
	"github.com/LeakIX/ip4scout/certificates"
	"os"
)

func main() { os.Exit(certificates.Main(os.Args[1:])) }
