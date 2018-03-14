package main

import (
	"log"
	"os"
	"path/filepath"
	"text/template"

	"github.com/midbel/cli"
	"github.com/midbel/ldap"
)

var (
	User, Passwd, Host string
	TryTLS, ForceTLS   bool
)

var commands = []*cli.Command{
	{
		Usage: "list [-u] [-p] [-s] [-f] [-z] [-zz] <node> <filter>",
		Short: "search for a specific node",
		Run:   List,
	},
	{
		Usage: "find [-u] [-p] [-s] [-f] [-z] [-zz] <node>",
		Short: "search for a specific node",
		Run:   Find,
	},
	{
		Usage: "compare [-u] [-p] [-s] [-z] [-zz] <node> <attr> <value>",
		Short: "check value of an attribute for the given node",
		Run:   Compare,
	},
	{
		Usage: "rename [-u] [-p] [-s] [-k] [-z] [-zz] <node> <rdn>",
		Short: "modify the dn of a node with a new rdn",
		Run:   Rename,
	},
	{
		Usage: "delete [-u] [-p] [-s] [-r] [-z] [-zz] <node>",
		Short: "delete a node from the DIT",
		Run:   Delete,
	},
	{
		Usage: "add [-u] [-p] [-s] [-c] [-z] [-zz] <ldif>",
		Short: "add a new entry into the DIT",
		Run:   Add,
	},
	{
		Usage: "modify [-u] [-p] [-s] [-c] [-z] [-zz] <ldif>",
		Short: "modify a node in the DIT",
		Run:   Modify,
	},
	{
		Usage: "passwd [-u] [-p] [-s] [-a] [-z] [-zz] <node>",
		Short: "update password of a node",
		Run:   Password,
	},
	{
		Usage: "serve <addr> <directory...>",
		Short: "run a web server to access ldap servers",
		Run:   nil,
	},
}

const helpText = `{{.Name}} performs operations on the DIT of a LDAP server.

Usage:

  {{.Name}} command [arguments]

The commands are:

{{range .Commands}}{{printf "  %-9s %s" .String .Short}}
{{end}}

Use {{.Name}} [command] -h for more information about its usage.
`

func main() {
	log.SetFlags(0)
	usage := func() {
		data := struct {
			Name     string
			Commands []*cli.Command
		}{
			Name:     filepath.Base(os.Args[0]),
			Commands: commands,
		}
		t := template.Must(template.New("help").Parse(helpText))
		t.Execute(os.Stderr, data)

		os.Exit(2)
	}
	if err := cli.Run(commands, usage, addCommonOptions); err != nil {
		log.Fatalln(err)
	}
}

func Client() (*ldap.Client, error) {
	var (
		c   *ldap.Client
		err error
	)
	switch {
	case TryTLS, ForceTLS:
		if c, err = ldap.Dial(Host); err != nil {
			break
		}
		if err = c.StartTLS(ForceTLS); err != nil {
			break
		}
		if err = c.Bind(User, Passwd); err != nil {
			break
		}
	default:
		c, err = ldap.Bind(Host, User, Passwd)
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func addCommonOptions(cmd *cli.Command) error {
	cmd.Flag.StringVar(&User, "u", User, "user")
	cmd.Flag.StringVar(&Passwd, "p", Passwd, "password")
	cmd.Flag.StringVar(&Host, "s", "localhost:389", "host")
	cmd.Flag.BoolVar(&TryTLS, "z", TryTLS, "try start tls")
	cmd.Flag.BoolVar(&ForceTLS, "zz", ForceTLS, "force start tls")

	return nil
}
