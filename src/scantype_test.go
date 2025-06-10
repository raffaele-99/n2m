package main

import (
	"fmt"
	"testing"
)

func TestDetermineScanType(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		expected string
	}{
		{
			name:     "Basic SYN scan",
			command:  "nmap -sS 192.168.1.1",
			expected: "TCP Top 1000, SYN Scan",
		},
		{
			name:     "TCP + UDP combined",
			command:  "sudo nmap -sUT -sCO -sV --top-ports 1000 localhost",
			expected: "UDP + TCP + IP Protocol Top 1000, Connect Scan, Script Scan, Version Detection",
		},
		{
			name:     "UDP and TCP Connect",
			command:  "nmap -sUT 192.168.1.1",
			expected: "UDP + TCP Top 1000, Connect Scan",
		},
		{
			name:     "Script and Version combined flag",
			command:  "nmap -sCV 192.168.1.1",
			expected: "TCP Top 1000, Script Scan, Version Detection",
		},
		{
			name:     "All ports SYN scan",
			command:  "nmap -sS -p- 192.168.1.1",
			expected: "TCP All Ports, SYN Scan",
		},
		{
			name:     "Fast scan with OS detection",
			command:  "nmap -F -O 192.168.1.1",
			expected: "TCP Top 100, OS Detection",
		},
		{
			name:     "Multiple TCP techniques",
			command:  "nmap -sA -sN -sF -sX --top-ports 500 192.168.1.1",
			expected: "TCP Top 500, ACK/Null/FIN/Xmas Scan",
		},
		{
			name:     "Aggressive scan",
			command:  "nmap -A 192.168.1.1",
			expected: "TCP Top 1000, Script Scan, OS + Version Detection",
		},
		{
			name:     "UDP scan with version detection",
			command:  "nmap -sU -sV --top-ports 100 192.168.1.1",
			expected: "UDP Top 100, Version Detection",
		},
		{
			name:     "SCTP scan types",
			command:  "nmap -sY -sZ 192.168.1.1",
			expected: "SCTP + SCTP Cookie Echo Top 1000",
		},
		{
			name:     "Custom port range",
			command:  "nmap -p 80,443,8080 192.168.1.1",
			expected: "TCP Custom Ports",
		},
		{
			name:     "Single port scan",
			command:  "nmap -p 22 192.168.1.1",
			expected: "TCP Port 22",
		},
		{
			name:     "Combined everything",
			command:  "nmap -sSUACNFXWMVO -p- --script=vuln 192.168.1.1",
			expected: "UDP + IP Protocol All Ports, SYN/ACK/Null/FIN/Xmas/Window/Maimon Scan, Script Scan, OS + Version Detection",
		},
		{
			name:     "No scan type specified with version",
			command:  "nmap -sV 192.168.1.1",
			expected: "TCP Top 1000, Version Detection",
		},
		{
			name:     "TCP Connect with scripts",
			command:  "nmap -sT -sC --top-ports 20 192.168.1.1",
			expected: "TCP Top 20, Connect Scan, Script Scan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineScanType(tt.command)
			if result != tt.expected {
				t.Errorf("\nCommand:  %s\nExpected: %s\nGot:      %s", tt.command, tt.expected, result)
			}
		})
	}
}

// Run this function to see all test outputs
func ExampleDetermineScanType() {
	commands := []string{
		"sudo nmap -sUT -sCO -sV --top-ports 1000 localhost",
		"nmap -sCV 192.168.1.1",
		"nmap -sS -p- 192.168.1.1",
		"nmap -A -T4 192.168.1.1",
		"nmap -sSUACNFXWMVO -p- --script=vuln 192.168.1.1",
	}

	for _, cmd := range commands {
		fmt.Printf("Command: %s\nType: %s\n\n", cmd, determineScanType(cmd))
	}
}
