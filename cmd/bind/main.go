package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/midbel/ldap"
)

func main() {
	var (
		user = flag.String("u", "", "user")
		pass = flag.String("p", "", "password")
	)
	flag.Parse()

	c, err := ldap.Bind(flag.Arg(0), *user, *pass)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	c.Unbind()
}
