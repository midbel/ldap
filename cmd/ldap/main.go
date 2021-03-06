package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/midbel/cli"
	"github.com/midbel/ldap"
	"github.com/midbel/strrand"
)

const (
	scopeBase   = "base"
	scopeSingle = "single"
	scopeOne    = "one"
	scopeWhole  = "whole"
	scopeTree   = "subtree"
)

const (
	supportedFeatures   = "supportedFeatures"
	supportedControls   = "supportedControl"
	supportedExtensions = "supportedExtension"
)

type Filter struct {
	ldap.Filter
}

func (f *Filter) Set(str string) error {
	fil, err := ldap.ParseFilter(str)
	if err == nil {
		f.Filter = fil
	}
	return err
}

func (f *Filter) String() string {
	return "filter"
}

func (f *Filter) Control() ldap.Control {
	if f.Filter == nil {
		f.Filter = ldap.Present("objectClass")
	}
	return ldap.Assert(f.Filter)
}

func (f *Filter) Option() ldap.SearchOption {
	if f.Filter == nil {
		return nil
	}
	return ldap.WithControl(f.Control())
}

type OrderBy struct {
	Keys []ldap.SortKey
}

func (o *OrderBy) Set(str string) error {
	for _, str := range strings.Split(str, ",") {
		o.Keys = append(o.Keys, ldap.ParseSortKey(str))
	}
	return nil
}

func (o *OrderBy) String() string {
	return "order by"
}

func (o *OrderBy) Option() ldap.SearchOption {
	if len(o.Keys) == 0 {
		return nil
	}
	return ldap.WithControl(ldap.Sort(o.Keys...))
}

type Scope struct {
	Scope ldap.Scope
}

func (s *Scope) Set(str string) error {
	switch strings.ToLower(str) {
	case "", scopeBase:
		s.Scope = ldap.ScopeBase
	case scopeOne, scopeSingle:
		s.Scope = ldap.ScopeSingle
	case scopeWhole, scopeTree:
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
	Attrs   []string
	Filters []ldap.Filter
}

func (a *Attributes) Set(str string) error {
	for _, attr := range strings.Split(str, ",") {
		var filter ldap.Filter
		if x := strings.Index(attr, "("); x >= 0 {
			f, err := ldap.ParseFilter(attr[x:])
			if err != nil {
				return err
			}
			attr, filter = attr[:x], f
		}
		a.Attrs = append(a.Attrs, strings.TrimSpace(attr))
		if filter != nil {
			a.Filters = append(a.Filters, filter)
		}
	}
	return nil
}

func (a *Attributes) String() string {
	return strings.Join(a.Attrs, ", ")
}

func (a *Attributes) Option() []ldap.SearchOption {
	options := []ldap.SearchOption{
		ldap.WithAttributes(a.Attrs),
	}
	if len(a.Filters) > 0 {
		options = append(options, ldap.WithControl(ldap.FilterValues(a.Filters)))
	}
	return options
}

type Client struct {
	*ldap.Client

	User string
	Pass string
	Cert string
	Addr string
	TLS  bool
}

func (c *Client) Search(base string, options []ldap.SearchOption) error {
	es, _, err := c.Client.Search(base, options...)
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

func (c *Client) SupportedControls() error {
	return c.searchFeatures(supportedControls, "C", ldap.ControlNames)
}

func (c *Client) SupportedExtensions() error {
	return c.searchFeatures(supportedExtensions, "E", ldap.ExtensionNames)
}

func (c *Client) SupportedFeatures() error {
	return c.searchFeatures(supportedFeatures, "F", ldap.FeatureNames)
}

func (c *Client) Bind() error {
	var err error
	if c.TLS {
		cfg := tls.Config{
			InsecureSkipVerify: true,
		}
		c.Client, err = ldap.BindTLS(c.Addr, c.User, c.Pass, &cfg)
	} else {
		c.Client, err = ldap.Bind(c.Addr, c.User, c.Pass)
	}
	return err
}

func (c *Client) ExecFromReader(r io.Reader) error {
	return ldap.ReadLDIF(r, func(ct ldap.ChangeType, cg ldap.Change) error {
		var err error
		switch ct {
		case ldap.ModAdd:
			attrs := make([]ldap.Attribute, len(cg.Attrs))
			for i := range cg.Attrs {
				attrs[i] = cg.Attrs[i].Attribute
			}
			_, err = c.Client.Add(cg.Name, attrs)
		case ldap.ModDelete:
			_, err = c.Client.Delete(cg.Name)
		case ldap.ModReplace:
			_, err = c.Client.Modify(cg.Name, cg.Attrs)
		default:
			err = fmt.Errorf("unsupported/unknown action")
		}
		return err
	})
}

func (c *Client) ExecFromFile(file string) error {
	r, err := os.Open(file)
	if err != nil {
		return err
	}
	defer r.Close()
	return c.ExecFromReader(r)
}

func (c *Client) searchFeatures(attr, prefix string, names map[string]string) error {
	var (
		list  = ldap.WithAttributes([]string{attr})
		lim   = ldap.WithLimit(1)
		scope = ldap.WithScope(ldap.ScopeBase)
	)
	es, _, err := c.Client.Search("", list, lim, scope)
	if err != nil {
		return err
	}
	if len(es) == 0 {
		return nil
	}
	return PrintFeatures(es[0], attr, prefix, names)
}

var commands = []*cli.Command{
	{
		Usage: "bind [-u] [-p] [-r]",
		Alias: []string{"auth"},
		Short: "authenticate",
		Run:   runBind,
	},
	{
		Usage: "search [-u] [-p] [-r] [-t] [-a] [-s] <base> <filter>",
		Alias: []string{"filter", "find"},
		Short: "search for entries in directory",
		Run:   runSearch,
	},
	{
		Usage: "support [-u] [-p] [-r] [-e] [-f] [-c] [-a]",
		Short: "get list of supported features",
		Run:   runSupported,
	},
	{
		Usage: "compare [-u] [-p] [-r] <base> <assertion...>",
		Alias: []string{"cmp"},
		Short: "compare entry's attributes with assertion",
		Run:   runCompare,
	},
	{
		Usage: "delete [-u] [-p] [-r] <dn...>",
		Alias: []string{"rm", "del", "remove"},
		Short: "remove entries from directory",
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
		Short: "execute given operations to directory",
		Run:   runExec,
	},
	{
		Usage: "password [-u] [-p] [-r] [<dn>]",
		Short: "modify password",
		Run:   runModifyPasswd,
	},
	{
		Usage: "whoami [-u] [-p] [-r] ",
		Short: "whoami request",
		Run:   runWhoami,
	},
	// {
	// 	Usage: "explode <dn...>",
	// 	Short: "explode dn components",
	// 	Run:   runExplode,
	// },
	// {
	// 	Usage: "passwd [-a] [-s]",
	// 	Short: "create password",
	// 	Run:   runPasswd,
	// },
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

func runModifyPasswd(cmd *cli.Command, args []string) error {
	var (
		client Client
		filter Filter
	)
	cmd.Flag.Var(&filter, "f", "assertion filter")
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	cmd.Flag.BoolVar(&client.TLS, "z", false, "start tls")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()

	var (
		user = client.User
		old  = client.Pass
		pass = strrand.String(12)
	)
	if cmd.Flag.NArg() > 0 {
		old = ""
		user = cmd.Flag.Arg(0)
	}
	_, err := client.ModifyPassword(user, old, pass, filter.Control())
	return err
}

func runBind(cmd *cli.Command, args []string) error {
	var (
		client Client
		filter Filter
	)
	cmd.Flag.Var(&filter, "f", "assertion filter")
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	cmd.Flag.BoolVar(&client.TLS, "z", false, "start tls")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	return client.Unbind()
}

func runWhoami(cmd *cli.Command, args []string) error {
	var (
		client Client
		filter Filter
	)
	cmd.Flag.Var(&filter, "f", "assertion filter")
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	cmd.Flag.BoolVar(&client.TLS, "z", false, "start tls")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()
	who, _, err := client.Whoami(filter.Control())
	if err == nil {
		fmt.Fprintln(os.Stdout, strings.TrimPrefix(who, "dn:"))
	}
	return err
}

func runExec(cmd *cli.Command, args []string) error {
	var (
		client Client
		filter Filter
		tx     bool
	)
	cmd.Flag.Var(&filter, "f", "assertion filter")
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	cmd.Flag.BoolVar(&client.TLS, "z", false, "start tls")
	cmd.Flag.BoolVar(&tx, "t", tx, "execute operation(s) in a transaction")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()
	var err error
	if tx {
		err = client.Begin()
		if err != nil {
			return err
		}
	}
	if cmd.Flag.NArg() == 0 {
		err = client.ExecFromReader(os.Stdin)
	} else {
		err = client.ExecFromFile(cmd.Flag.Arg(0))
	}
	if tx {
		if err == nil {
			err = client.Commit()
		} else {
			err = client.Rollback()
		}
	}
	return err
}

func runMove(cmd *cli.Command, args []string) error {
	var (
		client Client
		filter Filter
	)
	cmd.Flag.Var(&filter, "f", "assertion filter")
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	cmd.Flag.BoolVar(&client.TLS, "z", false, "start tls")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()

	_, err := client.Move(cmd.Flag.Arg(0), cmd.Flag.Arg(1), filter.Control())
	return err
}

func runRename(cmd *cli.Command, args []string) error {
	var (
		keep   bool
		client Client
		filter Filter
	)
	cmd.Flag.Var(&filter, "f", "assertion filter")
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	cmd.Flag.BoolVar(&keep, "k", false, "keep old rdn")
	cmd.Flag.BoolVar(&client.TLS, "z", false, "start tls")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()

	_, err := client.Rename(cmd.Flag.Arg(0), cmd.Flag.Arg(1), keep, filter.Control())
	return err
}

func runDelete(cmd *cli.Command, args []string) error {
	var (
		client Client
		filter Filter
	)
	cmd.Flag.Var(&filter, "f", "assertion filter")
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	cmd.Flag.BoolVar(&client.TLS, "z", false, "start tls")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()

	for _, a := range cmd.Flag.Args() {
		if _, err := client.Delete(a, filter.Control()); err != nil {
			fmt.Fprintf(os.Stderr, "fail to delete %s: %s", a, err)
			fmt.Fprintln(os.Stderr)
		}
	}
	return nil
}

func runCompare(cmd *cli.Command, args []string) error {
	var (
		client Client
		filter Filter
	)
	cmd.Flag.Var(&filter, "f", "assert")
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	cmd.Flag.BoolVar(&client.TLS, "z", false, "start tls")
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
		ok, _, err := client.Compare(cmd.Flag.Arg(0), ava, filter.Control())
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

func runSupported(cmd *cli.Command, args []string) error {
	var (
		client        Client
		onlyExtension bool
		onlyFeature   bool
		onlyControl   bool
	)
	cmd.Flag.BoolVar(&onlyExtension, "e", onlyExtension, "show list of supported extension")
	cmd.Flag.BoolVar(&onlyControl, "c", onlyControl, "show list of supported controls")
	cmd.Flag.BoolVar(&onlyFeature, "f", onlyFeature, "show list of supported features")
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	cmd.Flag.BoolVar(&client.TLS, "z", false, "start tls")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	all := !onlyFeature && !onlyExtension && !onlyControl

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()

	var err error
	if onlyExtension || all {
		err = client.SupportedExtensions()
		if err != nil {
			return err
		}
	}
	if onlyFeature || all {
		err = client.SupportedFeatures()
		if err != nil {
			return err
		}
	}
	if onlyControl || all {
		err = client.SupportedControls()
		if err != nil {
			return err
		}
	}
	return nil
}

func runSearch(cmd *cli.Command, args []string) error {
	var (
		attr   Attributes
		scope  Scope
		order  OrderBy
		types  bool
		limit  int
		filter Filter
		client Client
	)
	cmd.Flag.Var(&filter, "f", "assertion filter")
	cmd.Flag.Var(&attr, "a", "attributes")
	cmd.Flag.Var(&scope, "s", "scope")
	cmd.Flag.Var(&order, "o", "sort")
	cmd.Flag.BoolVar(&types, "t", false, "types only")
	cmd.Flag.IntVar(&limit, "n", 0, "limit number of entries returned")
	cmd.Flag.StringVar(&client.Addr, "r", "localhost:389", "remote host")
	cmd.Flag.StringVar(&client.User, "u", "", "user")
	cmd.Flag.StringVar(&client.Pass, "p", "", "password")
	cmd.Flag.BoolVar(&client.TLS, "z", false, "start tls")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := client.Bind(); err != nil {
		return err
	}
	defer client.Unbind()

	options := []ldap.SearchOption{
		ldap.WithTypes(types),
		ldap.WithLimit(limit),
		scope.Option(),
	}
	if opt := order.Option(); opt != nil {
		options = append(options, opt)
	}
	if opt := filter.Option(); opt != nil {
		options = append(options, opt)
	}
	options = append(options, attr.Option()...)
	if cmd.Flag.NArg() > 1 {
		filter, err := ldap.ParseFilter(cmd.Flag.Arg(1))
		if err != nil {
			return err
		}
		options = append(options, ldap.WithFilter(filter))
	}
	return client.Search(cmd.Flag.Arg(0), options)
}

func PrintFeatures(e ldap.Entry, attr, prefix string, names map[string]string) error {
	sort.Slice(e.Attrs, func(i, j int) bool {
		return e.Attrs[i].Name < e.Attrs[j].Name
	})
	x := sort.Search(len(e.Attrs), func(i int) bool {
		return e.Attrs[i].Name >= attr
	})
	if x >= len(e.Attrs) || e.Attrs[x].Name != attr {
		return fmt.Errorf("%s: attribute not found", attr)
	}
	if names == nil {
		names = make(map[string]string)
	}
	for _, v := range e.Attrs[x].Values {
		if str := names[v]; str != "" {
			fmt.Printf("- %s: %s (%s)", prefix, str, v)
		} else {
			fmt.Printf("- %s: %s", prefix, v)
		}
		fmt.Println()
	}
	return nil
}

func PrintEntry(e ldap.Entry) {
	fmt.Fprintf(os.Stdout, "dn: %s", e.Name)
	if len(e.Attrs) == 0 {
		return
	}
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
