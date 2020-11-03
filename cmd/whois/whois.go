package main

import (
	"fmt"
	"os"

	"github.com/FlyinDoji/whois"
)

func main() {

	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stdout, "Usage:\twhois <domain name>")
		return
	}
	if s, r, err := whois.Whois(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stdout, err)
	} else {
		fmt.Fprintln(os.Stdout, "Queried ", s)
		fmt.Fprintln(os.Stdout, r)
	}
}
