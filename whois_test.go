package whois

import (
	"os"
	"testing"
)

func TestWhois(t *testing.T) {

	tests := []string{
		"verisign.com",
		"denic.de",
		"iana.org",
		"verisign.net",
		"nominet.uk",
		"nic.cz",
		"red.es",
	}

	for _, v := range tests {
		_, r, err := Whois(v)
		if err != nil {
			t.Errorf("Whois(%s):  %s", v, err.Error())
		}
		if r == "" {
			t.Errorf("Whois(%s): response empty", v)
		}
	}
}

// Must set env variables before running tests
func TestProxied(t *testing.T) {

	addr := os.Getenv("PROXY_ADDRESS")
	user := os.Getenv("PROXY_USER")
	passwd := os.Getenv("PROXY_PASSWORD")

	if addr == "" {
		t.Skipf("PROXY_ADDRESS not set, can't test ProxiedWhois")
	}

	tests := []string{
		"verisign.com",
		"denic.de",
		"iana.org",
		"verisign.net",
		"nominet.uk",
		"nic.cz",
		"red.es",
	}

	t.Logf("ADDR: %s, USER: %s, PASSWORD: %s", addr, user, passwd)
	if user == "" || passwd == "" {
		t.Log("Authentication variables not set")

		for _, v := range tests {
			_, r, err := Proxied(v, addr, nil)
			if err != nil {
				t.Errorf("ProxiedWhois(%s):  %s", v, err.Error())
			}
			if r == "" {
				t.Errorf("ProxiedWhois(%s): response empty", v)
			}
		}

	} else {
		auth := ProxyAuth(user, passwd)
		for _, v := range tests {
			_, r, err := Proxied(v, addr, auth)
			if err != nil {
				t.Errorf("ProxiedWhois(%s):  %s", v, err.Error())
			}
			if r == "" {
				t.Errorf("ProxiedWhois(%s): response empty", v)
			}
		}
	}

}
