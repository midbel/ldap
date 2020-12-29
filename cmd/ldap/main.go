package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/midbel/cli"
	"github.com/midbel/ldap"
)

type Scope struct {
	Scope ldap.Scope
}

func (s *Scope) Set(str string) error {
	switch strings.ToLower(str) {
	case "base", "":
		s.Scope = ldap.ScopeBase
	case "one", "single":
		s.Scope = ldap.ScopeSingle
	case "whole":
		s.Scope = ldap.ScopeWhole
	default:
		return fmt.Errorf("%s: invalid value for scope", str)
	}
	return nil
}

func (s *Scope) String() string {
	return "scope"
}

func (s *Scope) Option() ldap.SearchOption {
	return ldap.WithScope(s.Scope)
}

type Attributes struct {
	Attrs []string
}

func (a *Attributes) Set(str string) error {
	for _, attr := range strings.Split(str, ",") {
		a.Attrs = append(a.Attrs, strings.TrimSpace(attr))
	}
	return nil
}

func (a *Attributes) String() string {
	return "attributes"
}

func (a *Attributes) Option() ldap.SearchOption {
	return ldap.WithAttributes(a.Attrs)
}

var commands = []*cli.Command{
	{
		Usage: "search [-u] [-p] [-r] [-t] [-a] <base> <filter>",
		Alias: []string{"filter", "find"},
		Short: "search ldap",
		Run:   runSearch,
	},
	{
		Usage: "compare [-u] [-p] [-r] <base> <assertion...>",
		Alias: []string{"cmp"},
		Short: "compare ldap",
		Run:   runCompare,
	},
	{
		Usage: "delete [-u] [-p] [-r] <dn...>",
		Alias: []string{"rm", "del", "remove"},
		Short: "remove entries from ldap",
		Run:   runDelete,
	},
	{
		Usage: "bind [-u] [-p] [-r]",
		Alias: []string{"auth"},
		Short: "authenticate",
		Run:   runDelete,
	},
}

func main() {
	cli.RunAndExit(commands, cli.Usage("ldap", "", commands))
}

func runBind(cmd *cli.Command, args []string) error {
  var (
    remote = cmd.Flag.String("r", "localhost:389", "remote host")
    user   = cmd.Flag.String("u", "", "user")
    pass   = cmd.Flag.String("p", "", "password")
  )
  if err := cmd.Flag.Parse(args); err != nil {
    return err
  }

  c, err := ldap.Bind(*remote, *user, *pass)
  if err != nil {
    return err
  }
  return c.Unbind()
}

func runDelete(cmd *cli.Command, args []string) error {
	var (
		remote = cmd.Flag.String("r", "localhost:389", "remote host")
		user   = cmd.Flag.String("u", "", "user")
		pass   = cmd.Flag.String("p", "", "password")
	)
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	c, err := ldap.Bind(*remote, *user, *pass)
	if err != nil {
		return err
	}
	defer c.Unbind()

	for _, a := range cmd.Flag.Args() {
		if err := c.Delete(a); err != nil {
			fmt.Fprintf(os.Stderr, "fail to delete %s: %s", a, err)
			fmt.Fprintln(os.Stderr)
		}
	}
	return nil
}

func runCompare(cmd *cli.Command, args []string) error {
	var (
		remote = cmd.Flag.String("r", "localhost:389", "remote host")
		user   = cmd.Flag.String("u", "", "user")
		pass   = cmd.Flag.String("p", "", "password")
	)
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	c, err := ldap.Bind(*remote, *user, *pass)
	if err != nil {
		return err
	}
	defer c.Unbind()

	for i := 1; i < cmd.Flag.NArg(); i++ {
		ava, err := ldap.FromLDIF(cmd.Flag.Arg(i))
		if err != nil {
			return err
		}
		ok, err := c.Compare(cmd.Flag.Arg(0), ava)
		if err != nil {
			return err
		}
		if ok {
			fmt.Fprintf(os.Stdout, "TRUE:  %s", cmd.Flag.Arg(i))
		} else {
			fmt.Fprintf(os.Stdout, "FALSE: %s", cmd.Flag.Arg(i))
		}
		fmt.Fprintln(os.Stdout)
	}
	return nil
}

func runSearch(cmd *cli.Command, args []string) error {
	var (
		attr   Attributes
		scope  Scope
		remote = cmd.Flag.String("r", "localhost:389", "remote host")
		user   = cmd.Flag.String("u", "", "user")
		pass   = cmd.Flag.String("p", "", "password")
		types  = cmd.Flag.Bool("t", false, "types only")
		limit  = cmd.Flag.Int("n", 0, "limit number of entries returned")
	)
	cmd.Flag.Var(&attr, "a", "")
	cmd.Flag.Var(&scope, "s", "")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	c, err := ldap.Bind(*remote, *user, *pass)
	if err != nil {
		return err
	}
	defer c.Unbind()

	options := []ldap.SearchOption{
		ldap.WithScope(ldap.ScopeWhole),
		ldap.WithTypes(*types),
    ldap.WithAttributes(attr.Attrs),
		attr.Option(),
		scope.Option(),
		ldap.WithLimit(*limit),
	}

	es, err := c.Search(cmd.Flag.Arg(0), options...)
	if err != nil {
		return err
	}
	for i, e := range es {
		if e.Name == flag.Arg(1) {
			continue
		}
		if i > 0 {
			fmt.Fprintln(os.Stdout)
		}
		PrintEntry(e)
	}
	return nil
}

func PrintEntry(e ldap.Entry) {
	fmt.Fprintf(os.Stdout, "dn: %s", e.Name)
	fmt.Fprintln(os.Stdout)
	for _, a := range e.Attrs {
		if len(a.Values) == 0 {
			a.Values = append(a.Values, "")
		}
		for _, v := range a.Values {
			fmt.Fprintf(os.Stdout, "%s: %s", a.Name, v)
			fmt.Fprintln(os.Stdout)
		}
	}
}
