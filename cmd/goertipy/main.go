package main

import (
	"fmt"
	"os"

	"github.com/slacker/goertipy/internal/commands"
	"github.com/spf13/cobra"
)

var version = "0.1.0"

func main() {
	rootCmd := &cobra.Command{
		Use:   "goertipy",
		Short: "AD CS enumeration and exploitation toolkit",
		Long: `Goertipy - Active Directory Certificate Services Toolkit

A Go implementation for enumerating and exploiting AD CS misconfigurations.
Similar to Certipy, but written in Go for portability and performance.`,
		Version: version,
	}

	// Add subcommands
	rootCmd.AddCommand(commands.NewFindCommand())
	rootCmd.AddCommand(commands.NewReqCommand())
	rootCmd.AddCommand(commands.NewAuthCommand())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
