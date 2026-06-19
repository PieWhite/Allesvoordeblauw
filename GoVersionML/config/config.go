package config

import (
	"flag"
	"fmt"
	"net"
	"strings"
)

// AppConfig holds the configuration state for the application.
// This struct encapsulates configuration, replacing the loose global parsing.
type AppConfig struct {
	OutputFile  string
	InputPath   string
	CpuProfile  string
	MemProfile  string
	SkipConfirm bool
	Subnet      string
}

// ParseFlags reads command-line flags and arguments, populating the AppConfig.
// ParseArgs takes a slice of strings (like os.Args[1:]) and a FlagSet.
// This makes it 100% testable without global hacks.
func (c *AppConfig) ParseArgs(args []string) error {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)

	fs.StringVar(&c.OutputFile, "o", "", "Write results to a text file: -o yourresults.txt")
	fs.StringVar(&c.CpuProfile, "cpuprofile", "", "Write CPU profile to file")
	fs.StringVar(&c.MemProfile, "memprofile", "", "Write memory profile to file")
	fs.StringVar(&c.Subnet, "subnet", "", "IP subnet to filter on (e.g. 192.251.0.0/16 or 196.251.x.x)")
	fs.BoolVar(&c.SkipConfirm, "y", false, "Skip confirmation prompt")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("you need to specify an input file")
	}
	c.InputPath = fs.Arg(0)
	return nil
}

// MatchSubnet checks if the given IP matches the subnet or wildcard prefix.
func MatchSubnet(ipStr string, subnetStr string) bool {
	if subnetStr == "" {
		return true
	}
	// Clean up whitespaces
	subnetStr = strings.TrimSpace(subnetStr)

	// Support standard CIDR notation first, e.g. "192.251.0.0/16"
	if strings.Contains(subnetStr, "/") {
		_, ipNet, err := net.ParseCIDR(subnetStr)
		if err == nil {
			ip := net.ParseIP(strings.TrimSpace(ipStr))
			if ip != nil {
				return ipNet.Contains(ip)
			}
		}
	}

	// Fallback: If it has wildcards like 'x', 'X', '*', replace/truncate them.
	// E.g. "192.251.x.x" or "192.251.*"
	wildcardIdx := strings.IndexAny(subnetStr, "xX*")
	var prefix string
	if wildcardIdx != -1 {
		prefix = subnetStr[:wildcardIdx]
	} else {
		prefix = subnetStr
	}

	// Ensure IP and prefix comparison is clean (e.g. string prefixes)
	return strings.HasPrefix(strings.TrimSpace(ipStr), prefix)
}
