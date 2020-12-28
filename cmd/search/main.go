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
	defer c.Unbind()

	es, err := c.Search(flag.Arg(1), ldap.WithScope(ldap.ScopeWhole))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
  for _, e := range es {
    fmt.Fprintf(os.Stdout, "%+v\n", e)
  }
}
