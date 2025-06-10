package main

import (
	"fmt"
	"regexp"
	"strings"
)

// determineScanType analyzes the nmap command and returns a formatted scan type description
func determineScanType(command string) string {
	// Parse all -s flags
	scanFlags := parseScanFlags(command)

	// 1. Protocols
	protocols := []string{}
	hasTCPTechnique := false

	// Check if any TCP technique is specified
	if scanFlags['T'] || scanFlags['S'] || scanFlags['A'] || scanFlags['N'] ||
		scanFlags['F'] || scanFlags['X'] || scanFlags['W'] || scanFlags['M'] {
		hasTCPTechnique = true
	}

	// Add protocols based on what's specified
	if scanFlags['U'] {
		protocols = append(protocols, "UDP")
		// If UDP is specified along with TCP techniques, also add TCP
		if hasTCPTechnique {
			protocols = append(protocols, "TCP")
		}
	} else if hasTCPTechnique {
		// Only TCP techniques specified
		protocols = append(protocols, "TCP")
	}

	if scanFlags['Y'] {
		protocols = append(protocols, "SCTP")
	}
	if scanFlags['Z'] {
		protocols = append(protocols, "SCTP Cookie Echo")
	}
	if scanFlags['O'] {
		protocols = append(protocols, "IP Protocol")
	}

	// If no scan type specified but has -sV or -sC, default to TCP
	if len(protocols) == 0 && (scanFlags['V'] || scanFlags['C']) {
		protocols = append(protocols, "TCP")
	}

	// 2. Port Range
	portRange := getPortRange(command)

	// 3. Techniques (TCP-specific scan types)
	techniques := []string{}
	if scanFlags['S'] {
		techniques = append(techniques, "SYN")
	}
	if scanFlags['T'] {
		techniques = append(techniques, "Connect")
	}
	if scanFlags['A'] {
		techniques = append(techniques, "ACK")
	}
	if scanFlags['N'] {
		techniques = append(techniques, "Null")
	}
	if scanFlags['F'] {
		techniques = append(techniques, "FIN")
	}
	if scanFlags['X'] {
		techniques = append(techniques, "Xmas")
	}
	if scanFlags['W'] {
		techniques = append(techniques, "Window")
	}
	if scanFlags['M'] {
		techniques = append(techniques, "Maimon")
	}

	// 4. Script/Version/OS Detection
	features := []string{}
	if scanFlags['C'] {
		features = append(features, "Script Scan")
	}
	if scanFlags['V'] {
		features = append(features, "Version Detection")
	}
	// Check for -O flag (not in -s group) or -A flag
	if hasStandaloneFlag(command, "-O") || hasStandaloneFlag(command, "-A") {
		features = append(features, "OS Detection")
	}
	// -A also implies script scan and version detection
	if hasStandaloneFlag(command, "-A") {
		if !scanFlags['C'] {
			features = append(features, "Script Scan")
		}
		if !scanFlags['V'] {
			features = append(features, "Version Detection")
		}
	}

	// Build result string
	var result []string

	// Add protocols + port range
	if len(protocols) > 0 {
		// Build protocol string with techniques
		protocolParts := []string{}
		for _, protocol := range protocols {
			if protocol == "TCP" && len(techniques) > 0 {
				// Add techniques in parentheses after TCP
				protocolParts = append(protocolParts, fmt.Sprintf("TCP (%s)", strings.Join(techniques, "/")))
			} else {
				protocolParts = append(protocolParts, protocol)
			}
		}
		protocolStr := strings.Join(protocolParts, " + ")
		result = append(result, protocolStr+" "+portRange)
	} else {
		// Default to TCP if no protocol specified
		if len(techniques) > 0 {
			result = append(result, fmt.Sprintf("TCP (%s) %s", strings.Join(techniques, "/"), portRange))
		} else {
			result = append(result, "TCP "+portRange)
		}
	}

	// Add features - handle special combinations
	if contains(features, "OS Detection") && contains(features, "Version Detection") {
		// Remove OS and Version from features to combine them
		filteredFeatures := []string{}
		for _, f := range features {
			if f != "OS Detection" && f != "Version Detection" {
				filteredFeatures = append(filteredFeatures, f)
			}
		}
		result = append(result, filteredFeatures...)
		result = append(result, "OS + Version Detection")
	} else {
		result = append(result, features...)
	}

	return strings.Join(result, ", ")
}

// parseScanFlags extracts all characters following -s in the command
func parseScanFlags(command string) map[rune]bool {
	flags := make(map[rune]bool)

	for i := 0; i < len(command)-2; i++ {
		if command[i:i+2] == "-s" {
			j := i + 2
			for j < len(command) && isLetter(command[j]) {
				flags[rune(command[j])] = true
				j++
			}
		}
	}

	return flags
}

// getPortRange determines the port range from the command
func getPortRange(command string) string {
	if strings.Contains(command, "-p-") {
		return "All Ports"
	}

	// Check for --top-ports
	if strings.Contains(command, "--top-ports") {
		re := regexp.MustCompile(`--top-ports\s+(\d+)`)
		if match := re.FindStringSubmatch(command); len(match) > 1 {
			return "Top " + match[1]
		}
	}

	// Check for -F (fast scan)
	if hasStandaloneFlag(command, "-F") {
		return "Top 100"
	}

	// Check for custom port specification
	if strings.Contains(command, " -p") {
		// Try to extract port specification
		re := regexp.MustCompile(`-p\s*([^\s]+)`)
		if match := re.FindStringSubmatch(command); len(match) > 1 {
			ports := match[1]
			// Check if it's a range or list
			if strings.Contains(ports, "-") || strings.Contains(ports, ",") {
				return "Custom Ports"
			}
			// Single port
			return "Port " + ports
		}
		return "Custom Ports"
	}

	// Default
	return "Top 1000"
}

// hasStandaloneFlag checks if a standalone flag exists in the command
func hasStandaloneFlag(command, flag string) bool {
	// Check for flag followed by space or at end of string
	if strings.Contains(command, flag+" ") || strings.HasSuffix(command, flag) {
		return true
	}
	// Check if flag appears before another flag
	re := regexp.MustCompile(regexp.QuoteMeta(flag) + `\s+-`)
	return re.MatchString(command)
}

// isLetter checks if a byte is an ASCII letter
func isLetter(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// contains checks if a string slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
