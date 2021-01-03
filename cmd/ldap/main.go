package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"flag"
	"fmt"
  "io"
	"os"
	"strings"

	"github.com/midbel/cli"
	"github.com/midbel/ldap"
	"github.com/midbel/strrand"
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

type Client struct {
	*ldap.Client

	User string
	Pass string
	Cert string
	Addr string
}

func (c *Client) Bind() error {
	client, err := ldap.Bind(c.Addr, c.User, c.Pass)
	if err == nil {
		c.Client = client
	}
	return err
}

func (c *Client) ExecFromReader(r io.Reader) error {
  return nil
}

func (c *Client) ExecFromFile(file string) error {
  r, err := os.Open(file)
  if err != nil {
    return err
  }
  defer r.Close()
  return c.ExecFromReader(r)
}

func (c *Client) AddFromReader(r io.Reader) error {
	return nil
}

func (c *Client) AddFromFile(file string) error {
  r, err := os.Open(file)
  if err != nil {
    return err
  }
  defer r.Close()
	return c.AddFromReader(r)
}

func (c *Client) ModifyFromReader(r io.Reader) error {
	return nil
}

func (c *Client) ModifyFromFile(file string) error {
  r, err := os.Open(file)
  if err != nil {
    return err
  }
  defer r.Close()
  return c.ModifyFromReader(r)
}

var commands = []*cli.Command{
	{
		Usage: "bind [-u] [-p] [-r]",
		Alias: []string{"auth"},
		Short: "authenticate",
		Run:   runDelete,
	},
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
		Usage: "add [-u] [-p] [-r] <file|->",
		Short: "add entries to a directory",
		Run:   runAdd,
	},
	{
		Usage: "modify [-u] [-p] [-r] <file|->",
		Short: "modify entries in a ldap",
		Run:   runModify,
	},
	{
		Usage: "delete [-u] [-p] [-r] <dn...>",
		Alias: []string{"rm", "del", "remove"},
		Short: "remove entries from ldap",
		Run:   runDelete,
	},
	{
		Usage: "rename [-u] [-p] [-r] [-k] <dn> <rdn>",
		Short: "rename entry",
		Run:   runRename,
	},
	{
		Usage: "move [-u] [-p] [-r] <dn> <parent>",
		Alias: []string{"mv"},
		Short: "move entry to new parent",
		Run:   runMove,
	},
  {
    Usage: "execute [-u] [-p] [-r] <file|->",
    Alias: []string{"exec"},
    Short: "execute ldap operations found in the given file",
    Run: runExec,
  },
	{
		Usage: "explode <dn...>",
		Short: "explode dn components",
		Run:   runExplode,
	},
	{
		Usage: "passwd [-a] [-s]",
		Short: "create password",
		Run:   runPasswd,
	},
}

func main() {
	cli.RunAndExit(commands, cli.Usage("ldap", "", commands))
}

func runPasswd(cmd *cli.Command, args []string) error {
	var (
		alg      = cmd.Flag.String("a", "plain", "algorithm")
		secret   = cmd.Flag.String("s", "", "secret")
		generate = cmd.Flag.Bool("g", false, "generate")
		length   = cmd.Flag.Int("n", 8, "length")
	)
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	if *generate {
		fmt.Fprintln(os.Stdout, strrand.String(*length))
		return nil
	}
	if *secret == "" {
		return nil
	}
	var passwd []byte
	switch strings.ToLower(*alg) {
	case "md5":
		sum := md5.Sum([]byte(*secret))
		passwd = sum[:]
	case "sha":
		sum := sha1.Sum([]byte(*secret))
		passwd = sum[:]
	case "", "plain":
		fmt.Fprintln(os.Stdout, *secret)
		return nil
	default:
		return fmt.Errorf("%s: unsupported algorithm", *alg)
	}
	fmt.Fprintf(os.Stdout, "{%s}%s", strings.ToUpper(*alg), base64.StdEncoding.EncodeToString(passwd))
	fmt.Fprintln(os.Stdout)
	return nil
}

func runExplode(cmd *cli.Command, args []string) error {
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	for _, a := range cmd.Flag.Args() {
		dn, err := ldap.Explode(a)
		if err != nil {
			fmt.Fprintln(os.Stderr, a, ":", err)
			continue
		}
		fmt.Fprintf(os.Stdout, "%s: %s", dn.RDN(), dn)
		fmt.Fprintln(os.Stdout)
	}
	return nil
}

func runBind(cmd *cli.Command, args []string) error {
	var client Client
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	return client.Unbind()
}

func runExec(cmd *cli.Command, args []string) error {
	var client Client
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()
  var err error
  if cmd.Flag.NArg() == 0 {
    err = client.ExecFromReader(os.Stdin)
  } else {
    err = client.ExecFromFile(cmd.Flag.Arg(0))
  }
  return err
}

func runMove(cmd *cli.Command, args []string) error {
	var client Client
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()

	return client.Move(cmd.Flag.Arg(0), cmd.Flag.Arg(1))
}

func runRename(cmd *cli.Command, args []string) error {
	var (
		client Client
		keep   bool
	)
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	cmd.Flag.BoolVar(&keep, "k", false, "keep old rdn")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()

	return client.Rename(cmd.Flag.Arg(0), cmd.Flag.Arg(1), keep)
}

func runDelete(cmd *cli.Command, args []string) error {
	var client Client
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()

	for _, a := range cmd.Flag.Args() {
		if err := client.Delete(a); err != nil {
			fmt.Fprintf(os.Stderr, "fail to delete %s: %s", a, err)
			fmt.Fprintln(os.Stderr)
		}
	}
	return nil
}

func runAdd(cmd *cli.Command, args []string) error {
	var client Client
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()

	var err error
	if cmd.Flag.NArg() == 0 {
		err = client.AddFromReader(os.Stdin)
	} else {
		err = client.AddFromFile(cmd.Flag.Arg(0))
	}
	return err
}

func runModify(cmd *cli.Command, args []string) error {
	var client Client
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()

	var err error
	if cmd.Flag.NArg() == 0 {
		err = client.ModifyFromReader(os.Stdin)
	} else {
		err = client.ModifyFromFile(cmd.Flag.Arg(0))
	}
	return err
}

func runCompare(cmd *cli.Command, args []string) error {
	var client Client
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()

	for i := 1; i < cmd.Flag.NArg(); i++ {
		ava, err := ldap.FromLDIF(cmd.Flag.Arg(i))
		if err != nil {
			return err
		}
		ok, err := client.Compare(cmd.Flag.Arg(0), ava)
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
		types  bool
		limit  int
		client Client
	)
	cmd.Flag.Var(&attr, "a", "")
	cmd.Flag.Var(&scope, "s", "")
	cmd.Flag.BoolVar(&types, "t", false, "types only")
	cmd.Flag.IntVar(&limit, "n", 0, "limit number of entries returned")
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()

	options := []ldap.SearchOption{
		ldap.WithScope(ldap.ScopeWhole),
		ldap.WithTypes(types),
		ldap.WithAttributes(attr.Attrs),
		attr.Option(),
		scope.Option(),
		ldap.WithLimit(limit),
	}

	es, err := client.Search(cmd.Flag.Arg(0), options...)
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
