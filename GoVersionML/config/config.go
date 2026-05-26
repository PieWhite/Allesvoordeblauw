package config

import (
	"flag"
	"fmt"
	"os"
)

// AppConfig holds the configuration state for the application.
// This struct encapsulates configuration, replacing the loose global parsing.
type AppConfig struct {
	ModelPath  string
	OutputFile string
	InputPath  string
	CpuProfile string
	MemProfile string
}

// ParseFlags reads command-line flags and arguments, populating the AppConfig.
// ParseArgs takes a slice of strings (like os.Args[1:]) and a FlagSet.
// This makes it 100% testable without global hacks.
func (c *AppConfig) ParseArgs(args []string) error {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)

	fs.StringVar(&c.ModelPath, "m", "../Xgboost/botnet_xgboost.json", "Path to XGBoost JSON: -m ./Xgboost/your-xgboost-name.json")
	fs.StringVar(&c.OutputFile, "o", "", "Write results to a text file: -o yourresults.txt")
	fs.StringVar(&c.CpuProfile, "cpuprofile", "", "Write CPU profile to file")
	fs.StringVar(&c.MemProfile, "memprofile", "", "Write memory profile to file")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Resilient model path fallback for CLI/standard scanner run
	// Only fallback if the default path is selected and does not exist in the filesystem
	if c.ModelPath == "../Xgboost/botnet_xgboost.json" {
		if _, err := os.Stat(c.ModelPath); os.IsNotExist(err) {
			p2 := "./Xgboost/botnet_xgboost.json"
			if _, err := os.Stat(p2); err == nil {
				c.ModelPath = p2
			}
		}
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("you need to specify an input file")
	}
	c.InputPath = fs.Arg(0)
	return nil
}
