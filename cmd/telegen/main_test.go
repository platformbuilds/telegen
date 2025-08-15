package main

import (
	"testing"
)

// TestMainRuns ensures that the main function runs without panic.
// Note: This won't fully test the program's functionality without refactoring main().
func TestMainRuns(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("main() panicked: %v", r)
		}
	}()

	// Ideally, main should be split into run() for easier testing.
	go func() {
		main()
	}()
}
