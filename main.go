package main

import (
	"fmt"
	"os"

	"github.com/bluenviron/mediamtx/internal/core"
)

const Version = "v1.0.0.0"

func main() {
	fmt.Println("main.go> main(): Begin")
	fmt.Println("main.go> Application Version:", Version)
	fmt.Println("Application Version:", Version)
	s, ok := core.New(os.Args[1:])
	if !ok {
		fmt.Println("main.go> main(): End-1")
		os.Exit(1)
	}
	s.Wait()
	fmt.Println("main.go> main(): End-99")
}
