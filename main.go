package main

import (
	"flag"
	"multims/cmd"
)

func main() {
	native := flag.Bool("native", false, "Start as native messaging host")
	flag.Parse()

	if *native {
		cmd.StartNativeHost()
	} else {
		cmd.Execute()
	}
}
