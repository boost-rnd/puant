package main

import "fmt"

// This is a benign Go file for testing.
// It does not contain any PUA characters.

func main() {
	greet("World")
	// some unicode characters
	सामान := "stuff"
	fmt.Println(सामान)
}

func greet(name string) {
	fmt.Printf("Hello, %s!\n", name)
}

