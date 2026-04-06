package config

import (
	"flag"
	"fmt"
)

// AppConfig holds the configuration state for the application.
// This struct encapsulates configuration, replacing the loose global parsing.
type AppConfig struct {
	ModelPath      string
	FeatureMapPath string
	OutputFile     string
	NetflowPath    string
}

// ParseFlags reads command-line flags and arguments, populating the AppConfig.
// ParseArgs takes a slice of strings (like os.Args[1:]) and a FlagSet.
// This makes it 100% testable without global hacks.
func (c *AppConfig) ParseArgs(args []string) error {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)

	fs.StringVar(&c.ModelPath, "m", "./Xgboost/xgboostv4.json", "Path to XGBoost JSON: -m ./Xgboost/your-xgboost-name.json")
	fs.StringVar(&c.FeatureMapPath, "fmap", "./Xgboost/xgboostv4.fmap", "Path to XGBoost feature map: -fmap ./Xgboost/xgboostv4.fmap")
	fs.StringVar(&c.OutputFile, "o", "", "Write results to a text file: -o yourresults.txt")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("you need to specify a netflow file")
	}
	c.NetflowPath = fs.Arg(0)
	return nil
}
