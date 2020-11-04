package main

import (
	"fmt"
	"os"

	"github.com/FlyinDoji/whois"

	"golang.org/x/net/proxy"
)

func main() {

	p := &proxy.Auth{}

	if len(os.Args) != 5 && len(os.Args) != 3 {
		fmt.Fprintln(os.Stdout, "Usage:\twhois <domain name> <proxy server> [user] [password]")
		return
	}

	if len(os.Args) == 5 {
		p = whois.ProxyAuth(os.Args[3], os.Args[4])
	}

	if s, r, err := whois.Proxied(os.Args[1], os.Args[2], p); err != nil {
		fmt.Fprintln(os.Stdout, err)
	} else {
		fmt.Fprintln(os.Stdout, "Queried ", s)
		fmt.Fprintln(os.Stdout, r)
	}
}
