package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"

	"github.com/midbel/ldap"
	"github.com/midbel/ldap/cmd/ldap/internal/ldif"
	"github.com/midbel/cli"
)

func Compare(cmd *cli.Command, args []string) error {
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	c, err := Client()
	if err != nil {
		return err
	}
	defer c.Unbind()

	b, err := c.Compare(cmd.Flag.Arg(0), cmd.Flag.Arg(1), cmd.Flag.Arg(2))
	if err != nil {
		return err
	}
	fmt.Printf("compare %t\n", b)
	return err
}

func Find(cmd *cli.Command, args []string) error {
	format := cmd.Flag.String("f", "ldif", "")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	c, err := Client()
	if err != nil {
		return err
	}
	defer c.Unbind()

	a := User != "" && Passwd != ""
	e, err := c.Find(cmd.Flag.Arg(0), a)
	if err != nil {
		return err
	}
	return printResults(os.Stdout, *format, []*ldap.Entry{e})
}

func List(cmd *cli.Command, args []string) error {
	format := cmd.Flag.String("f", "ldif", "")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	c, err := Client()
	if err != nil {
		return err
	}
	defer c.Unbind()

	s, err := ldap.Parse(cmd.Flag.Arg(1))
	if err != nil {
		return err
	}
	a := User != "" && Passwd != ""
	es, err := c.FindAll(cmd.Flag.Arg(0), s, a)
	if err != nil {
		return err
	}
	return printResults(os.Stdout, *format, es)
}

func printResults(w io.Writer, f string, rs []*ldap.Entry) error {
	var err error
	switch f {
	default:
		return fmt.Errorf("unsupported format provided: %s", f)
	case "ldif", "":
		if len(rs) == 1 {
			ldif.PrintEntry(w, rs[0])
		} else {
			ldif.PrintEntries(w, rs)
			fmt.Fprintf(w, "%d entries found\n", len(rs))
		}
	case "xml":
		e := xml.NewEncoder(w)
		e.Indent("", "  ")
		err = e.Encode(rs)
	case "json":
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		err = e.Encode(rs)
	}
	return err
}
