package config

import (
	"flag"
	"fmt"
	"strings"
)

// AppConfig holds the configuration state for the application.
// This struct encapsulates configuration, replacing the loose global parsing.
type AppConfig struct {
	ModelPath   string
	OutputFile  string
	NetflowPath string
	InputFormat string
}

// ParseFlags reads command-line flags and arguments, populating the AppConfig.
// ParseArgs takes a slice of strings (like os.Args[1:]) and a FlagSet.
// This makes it 100% testable without global hacks.
func (c *AppConfig) ParseArgs(args []string) error {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)

	fs.StringVar(&c.ModelPath, "m", "./Xgboost/botnet_xgboost.json", "Path to XGBoost JSON: -m ./Xgboost/your-xgboost-name.json")
	fs.StringVar(&c.OutputFile, "o", "", "Write results to a text file: -o yourresults.txt")
	fs.StringVar(&c.InputFormat, "input-format", "auto", "Input format override: auto|json|netflow")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("you need to specify a netflow file")
	}

	c.InputFormat = strings.ToLower(strings.TrimSpace(c.InputFormat))
	if c.InputFormat != "auto" && c.InputFormat != "json" && c.InputFormat != "netflow" {
		return fmt.Errorf("invalid input format %q: expected auto|json|netflow", c.InputFormat)
	}

	c.NetflowPath = fs.Arg(0)
	return nil
}
