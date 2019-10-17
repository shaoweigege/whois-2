package whois

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// Query parameters
const (
	PORT    = ":43"
	TIMEOUT = time.Duration(30) * time.Second
)

type tldServ struct {
	tld    string
	server string
}
type whoisDial func(network string, address string) (net.Conn, error)

var tldServers []tldServ

func extractTLD(domain string) (tldServ, bool) {

	for _, s := range tldServers {
		if len(s.tld) > len(domain) {
			continue
		}
		p := len(domain) - len(s.tld)
		if domain[p] != []byte(".")[0] {
			continue
		}
		if domain[p:] == s.tld {
			return s, true
		}
	}

	return tldServ{}, false
}

func queryServer(domain, server string, dial whoisDial) (string, string, error) {

	conn, err := dial("tcp", server+PORT)
	if err != nil {
		return "", "", err
	}
	_ = conn.SetDeadline(time.Now().Add(TIMEOUT))

	defer conn.Close()
	fmt.Fprintf(conn, "%s\r\n", domain)
	b, err := ioutil.ReadAll(conn)
	if err != nil {
		return "", "", err
	}

	return server, string(b), nil
}

func whois(domain string, dial whoisDial) (string, string, error) {

	if tld, ok := extractTLD(domain); ok {
		return queryServer(domain, tld.server, dial)
	}
	return "", "", fmt.Errorf("No whois server for %s", domain)
}

// Whois queries the database of the domain's tld
// Use the default net.Dial function to contact the whois server
func Whois(domain string) (string, string, error) {
	return whois(domain, net.Dial)
}

// Proxied queries the database of the domain's tld via SOCKS5 proxy
// Uses the proxy.Dialer.Dial function to contact the whois server
// p can be nil if no authentication is required
func Proxied(domain, proxyAddr string, p *proxy.Auth) (string, string, error) {

	socks, err := proxy.SOCKS5("tcp", proxyAddr, p, proxy.Direct)
	if err != nil {
		return "", "", err
	}
	return whois(domain, socks.Dial)
}

// OwnDialer supply your own dial function
func OwnDialer(domain string, dialFun whoisDial) (string, string, error) {
	return whois(domain, dialFun)
}

// ProxyAuth authentication object for ProxiedWhois
func ProxyAuth(user, passwd string) *proxy.Auth {
	return &proxy.Auth{User: user, Password: passwd}
}

// Load tld servers
func init() {
	for i, l := range strings.Split(tldServerList, "\n") {
		if l == "" {
			continue
		}
		kv := strings.Split(l, "\t")
		if len(kv) != 2 {
			log.Fatalf("whois:tldserv.go:tldServerList incorrect format %q at line %d", kv, i+1)
			continue
		}

		tldServers = append(tldServers, tldServ{tld: kv[0], server: kv[1]})
	}
}
