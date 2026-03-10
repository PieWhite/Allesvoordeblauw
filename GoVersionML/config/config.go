package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// AppConfig holds the configuration state for the application.
// This struct encapsulates configuration, replacing the loose global parsing.
type AppConfig struct {
	ModelPath   string
	OutputFile  string
	NetflowPath string
}

// ParseFlags reads command-line flags and arguments, populating the AppConfig.
func ParseFlags() (*AppConfig, error) {
	modelPath := flag.String("m", "./Xgboost/botnet_xgboost.json", "Path to the XGBoost JSON")
	outputFile := flag.String("o", "", "Write results to a text file")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <example_netflow.json>\nFlags:\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() == 0 {
		return nil, fmt.Errorf("You need to specify a netflow file to analyse")
	}
	if flag.NArg() > 1 {
		return nil, fmt.Errorf("You are not allowed to specify multiple files")
	}
	netflowPath := flag.Arg(0)

	return &AppConfig{
		ModelPath:   *modelPath,
		OutputFile:  *outputFile,
		NetflowPath: netflowPath,
	}, nil
}
