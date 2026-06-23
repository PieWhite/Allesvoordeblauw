/*
Package config provides the application configuration parsing, validation, and filter configuration.
It parses command-line arguments into AppConfig and matches network addresses against subnet criteria.
*/
package config

import (
	"flag"
	"fmt"
	"net"
	"strings"
)

type AppConfig struct {
	OutputFile  string
	InputPath   string
	CPUProfile  string
	MemProfile  string
	SkipConfirm bool
	Subnet      string
}

func (c *AppConfig) ParseArgs(args []string) error {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)

	fs.StringVar(&c.OutputFile, "o", "", "Write results to a text file: -o yourresults.txt")
	fs.StringVar(&c.CPUProfile, "cpuprofile", "", "Write CPU profile to file")
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

func MatchSubnet(ip, subnet string) bool {
	if subnet == "" {
		return true
	}
	subnet = strings.TrimSpace(subnet)

	if strings.Contains(subnet, "/") {
		_, ipNet, err := net.ParseCIDR(subnet)
		if err == nil {
			parsedIP := net.ParseIP(strings.TrimSpace(ip))
			if parsedIP != nil {
				return ipNet.Contains(parsedIP)
			}
		}
	}

	prefix := subnet
	if idx := strings.IndexAny(subnet, "xX*"); idx != -1 {
		prefix = subnet[:idx]
	}

	return strings.HasPrefix(strings.TrimSpace(ip), prefix)
}
