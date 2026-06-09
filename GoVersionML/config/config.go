package config

import (
	"flag"
	"fmt"
)

type AppConfig struct {
	OutputFile  string
	InputPath   string
	CpuProfile  string
	MemProfile  string
	SkipConfirm bool
}

func (c *AppConfig) ParseArgs(args []string) error {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)

	fs.StringVar(&c.OutputFile, "o", "", "Write results to a text file: -o yourresults.txt")
	fs.StringVar(&c.CpuProfile, "cpuprofile", "", "Write CPU profile to file")
	fs.StringVar(&c.MemProfile, "memprofile", "", "Write memory profile to file")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("you need to specify an input file")
	}
	c.InputPath = fs.Arg(0)
	return nil
}
