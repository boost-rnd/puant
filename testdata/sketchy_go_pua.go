package main

import (
	"encoding/base64"
	"fmt"
)

// Synthetic sketchy Go file with PUA obfuscation
func main() {
	// Normal code
	version := "1.0.0"
	fmt.Println("Version:", version)

	// This string has 90%+ PUA characters - should be detected
	obfuscatedPayload := `󠅦󠅑󠅢󠄐󠅏󠅏󠅓󠅢󠅕󠅑󠅤󠅕󠄭󠄿󠅒󠅚󠅕󠅓󠅤󠄞󠅓󠅢󠅕󠅑󠅤󠅕󠄫󠅦󠅑󠅢󠄐󠅏󠅏󠅔󠅕󠅖󠅀󠅢󠅟󠅠󠄭󠄿󠅒󠅚󠅕󠅓󠅤󠄞󠅔󠅕󠅖󠅙󠅞󠅕`

	// In real malware, this would decode and execute
	decodeAndExecute(obfuscatedPayload)
}

func decodeAndExecute(data string) {
	// Malicious function that would process the PUA string
	decoded, _ := base64.StdEncoding.DecodeString(data)
	fmt.Println(decoded) // Would actually execute code
}
