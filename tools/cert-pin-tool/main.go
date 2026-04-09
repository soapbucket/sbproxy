// Package main provides main functionality for the proxy.
package main

import (
	"flag"
	"fmt"
	"os"
	
	"github.com/soapbucket/sbproxy/internal/security/certpin"
)

func main() {
	host := flag.String("host", "", "Hostname to connect to")
	port := flag.String("port", "443", "Port to connect on")
	flag.Parse()
	
	if *host == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -host <hostname> [-port <port>]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nCompute certificate pins for a given host\n\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	
	fmt.Printf("Computing certificate pins for %s:%s...\n\n", *host, *port)
	
	pins, err := certpin.ComputePinFromConnection(*host, *port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	if len(pins) == 0 {
		fmt.Println("No certificates found")
		os.Exit(1)
	}
	
	fmt.Printf("Found %d certificate(s) in the chain:\n\n", len(pins))
	
	for i, pin := range pins {
		fmt.Printf("Certificate %d pin: %s\n", i, pin)
	}
	
	fmt.Printf("\nConfiguration example:\n\n")
	fmt.Printf("\"config\": {\n")
	fmt.Printf("  \"url\": \"https://%s\",\n", *host)
	fmt.Printf("  \"certificate_pinning\": {\n")
	fmt.Printf("    \"enabled\": true,\n")
	fmt.Printf("    \"pin_sha256\": \"%s\",\n", pins[0])
	if len(pins) > 1 {
		fmt.Printf("    \"backup_pins\": [")
		for i := 1; i < len(pins); i++ {
			if i > 1 {
				fmt.Printf(", ")
			}
			fmt.Printf("\"%s\"", pins[i])
		}
		fmt.Printf("]\n")
	}
	fmt.Printf("  }\n")
	fmt.Printf("}\n")
}



