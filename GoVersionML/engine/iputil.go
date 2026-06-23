// iputil.go provides zero-allocation IPv4 address parsing and formatting
// utilities operating on uint32 representations.
package engine

import "fmt"

func ParseIPv4(s string) (uint32, bool) {
	if len(s) == 0 {
		return 0, false
	}

	var ip uint32
	var octet uint32
	var dots int

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			octet = octet*10 + uint32(c-'0')
			if octet > 255 {
				return 0, false
			}
		} else if c == '.' {
			ip = (ip << 8) | octet
			octet = 0
			dots++
			if dots > 3 {
				return 0, false
			}
		} else {
			return 0, false
		}
	}

	if dots != 3 {
		return 0, false
	}

	ip = (ip << 8) | octet
	return ip, true
}

func FormatIPv4(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ip>>24,
		(ip>>16)&0xFF,
		(ip>>8)&0xFF,
		ip&0xFF,
	)
}
