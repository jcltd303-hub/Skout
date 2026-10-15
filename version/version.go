// Package version carries the Skout build version. Release tooling may
// overwrite Version at link time; the default is "dev".
package version

// Version is the human-readable build version printed by --version flags.
var Version = "dev"
