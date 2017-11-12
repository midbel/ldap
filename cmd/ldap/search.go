package main

import (
	"fmt"
	"os"

	"github.com/midbel/ldap"
	"github.com/midbel/ldap/cmd/ldap/internal/ldif"
	"github.com/midbel/rustine/cli"
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
	ldif.PrintEntry(os.Stdout, e)

	return nil
}

func List(cmd *cli.Command, args []string) error {
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
	ldif.PrintEntries(os.Stdout, es)
	fmt.Fprintf(os.Stdout, "%d entries found\n", len(es))
	return err
}
