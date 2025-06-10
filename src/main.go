package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type Port struct {
	Number   string
	Protocol string
	State    string
	Service  string
	Version  string
}

type NmapScan struct {
	Type    string
	Command string
	Output  string
	Ports   []Port
}

func parseNmapFile(filename string) (*NmapScan, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scan := &NmapScan{
		Output: "",
		Ports:  []Port{},
	}

	scanner := bufio.NewScanner(file)
	var output strings.Builder
	inPortSection := false
	portRegex := regexp.MustCompile(`^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?$`)
	commandRegex := regexp.MustCompile(`# Nmap .* scan initiated .* as: (.*)`)

	for scanner.Scan() {
		line := scanner.Text()
		output.WriteString(line + "\n")

		// Extract command
		if matches := commandRegex.FindStringSubmatch(line); matches != nil {
			scan.Command = matches[1]
		}

		// Detect port section
		if strings.HasPrefix(line, "PORT") && strings.Contains(line, "STATE") {
			inPortSection = true
			continue
		}

		// End of port section
		if inPortSection && (line == "" || strings.HasPrefix(line, "Service Info:") || strings.HasPrefix(line, "Host script results:") || strings.HasPrefix(line, "# Nmap done")) {
			inPortSection = false
		}

		// Parse ports
		if inPortSection {
			if matches := portRegex.FindStringSubmatch(line); matches != nil {
				port := Port{
					Number:   matches[1],
					Protocol: strings.ToUpper(matches[2]),
					State:    matches[3],
					Service:  strings.TrimSpace(matches[4]),
					Version:  "",
				}

				// If there's version info (5th capture group)
				if len(matches) > 5 && matches[5] != "" {
					port.Version = strings.TrimSpace(matches[5])
				}

				if port.State == "open" {
					scan.Ports = append(scan.Ports, port)
				}
			}
		}
	}

	scan.Output = strings.TrimSpace(output.String())

	// Determine scan type from command
	if scan.Command != "" {
		scan.Type = determineScanType(scan.Command)
	}

	return scan, scanner.Err()
}

func extractIPFromFile(filename string) string {
	// Try to extract IP from the nmap output first
	file, err := os.Open(filename)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	ipRegex := regexp.MustCompile(`Nmap scan report for (?:.*?\()?(\d+\.\d+\.\d+\.\d+)\)?`)
	hostnameRegex := regexp.MustCompile(`Nmap scan report for ([^\s]+)`)

	for scanner.Scan() {
		line := scanner.Text()
		// Try IP regex first
		if matches := ipRegex.FindStringSubmatch(line); matches != nil {
			return matches[1]
		}
		// Fall back to hostname
		if matches := hostnameRegex.FindStringSubmatch(line); matches != nil {
			return matches[1]
		}
	}

	// Try to extract from filename or command as fallback
	ipRegex = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
	if matches := ipRegex.FindStringSubmatch(filename); matches != nil {
		return matches[1]
	}

	return ""
}

func generateMarkdown(includeHeader bool, ip string, scans []*NmapScan) string {
	var output strings.Builder

	// Header
	if includeHeader {
		output.WriteString(fmt.Sprintf("# %s\n\n", ip))
		output.WriteString("# nmap\n")
	}

	// Add each scan type
	for _, scan := range scans {
		output.WriteString(fmt.Sprintf("## %s\n\n", scan.Type))

		// Add command in its own code block
		if scan.Command != "" {
			output.WriteString("```bash\n")
			output.WriteString(scan.Command)
			output.WriteString("\n```\n\n")
		}

		// Add scan output
		output.WriteString("```\n")
		output.WriteString(scan.Output)
		output.WriteString("\n```\n\n")
	}

	// Collect all unique ports from all scans
	portMap := make(map[string]Port)
	for _, scan := range scans {
		for _, port := range scan.Ports {
			// Use port number + protocol as key
			key := fmt.Sprintf("%s/%s", port.Number, port.Protocol)
			// If port already exists, update with version info if available
			if existing, exists := portMap[key]; exists {
				if existing.Version == "" && port.Version != "" {
					portMap[key] = port
				}
			} else {
				portMap[key] = port
			}
		}
	}

	// Create sorted list of ports
	var ports []Port
	for _, port := range portMap {
		ports = append(ports, port)
	}

	// Sort ports by number and protocol
	for i := 0; i < len(ports)-1; i++ {
		for j := 0; j < len(ports)-i-1; j++ {
			num1 := 0
			num2 := 0
			fmt.Sscanf(ports[j].Number, "%d", &num1)
			fmt.Sscanf(ports[j+1].Number, "%d", &num2)

			// Sort by number first, then by protocol (TCP before UDP)
			if num1 > num2 || (num1 == num2 && ports[j].Protocol > ports[j+1].Protocol) {
				ports[j], ports[j+1] = ports[j+1], ports[j]
			}
		}
	}

	// Add port sections
	for _, port := range ports {
		serviceName := port.Service
		if serviceName == "" {
			serviceName = "unknown"
		} else if serviceName == "tcpwrapped" {
			// Keep tcpwrapped as is
		} else if strings.Contains(serviceName, "?") {
			// Remove the question mark for uncertain services
			serviceName = strings.TrimSuffix(serviceName, "?")
		}

		output.WriteString(fmt.Sprintf("# %s/%s (%s)\n", port.Number, strings.ToLower(port.Protocol), serviceName))

		// Add version info if available
		if port.Version != "" {
			output.WriteString(fmt.Sprintf("**Version:** %s\n\n", port.Version))
		}

		output.WriteString("Manual investigation notes for this port go here\n\n")
	}

	return output.String()
}

func main() {
	var outputFile string
	var includeHeader bool
	flag.StringVar(&outputFile, "o", "", "Output markdown file (optional)")
	flag.BoolVar(&includeHeader, "header", false, "include a header with the IP address in the output (default: false)")
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Println("Usage: n2m [-o output.md] [-header] <nmap-file1> [nmap-file2] ...")
		fmt.Println("\nExample:")
		fmt.Println("  n2m all-tcp.nmap")
		fmt.Println("  n2m -o 10.10.11.174.md all-tcp.nmap top-1000-tcp-script-scan.nmap udp-1000.nmap")
		fmt.Println("  n2m -header -o results.md *.nmap")
		os.Exit(1)
	}

	// Parse all nmap files
	var scans []*NmapScan
	var ip string

	for _, filename := range flag.Args() {
		scan, err := parseNmapFile(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing %s: %v\n", filename, err)
			continue
		}
		scans = append(scans, scan)

		// Extract IP if not already found
		if ip == "" {
			ip = extractIPFromFile(filename)
		}
	}

	if len(scans) == 0 {
		fmt.Fprintln(os.Stderr, "No valid nmap scans found")
		os.Exit(1)
	}

	if ip == "" {
		if includeHeader {
			fmt.Fprintln(os.Stderr, "Warning: No IP address found in nmap files, using 'Unknown' in header")
			ip = "Unknown"
		}
	}

	// Generate markdown
	markdown := generateMarkdown(includeHeader, ip, scans)

	// Output
	if outputFile != "" {
		err := os.WriteFile(outputFile, []byte(markdown), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Markdown written to %s\n", outputFile)
	} else {
		fmt.Print(markdown)
	}
}
