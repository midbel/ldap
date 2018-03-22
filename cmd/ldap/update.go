package main

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/midbel/cli"
	"github.com/midbel/ldap"
)

func Password(cmd *cli.Command, args []string) error {
	old := cmd.Flag.String("o", "", "old passwd")
	upd := cmd.Flag.String("n", "", "new passwd")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	c, err := Client()
	if err != nil {
		return err
	}
	defer c.Unbind()
	return c.Passwd(cmd.Flag.Arg(0), *old, *upd)
}

func Modify(cmd *cli.Command, args []string) error {
	skip := cmd.Flag.Bool("c", false, "continuous operation mode")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	c, err := Client()
	if err != nil {
		return err
	}
	defer c.Unbind()

	var r *ldap.Reader
	if f, err := os.Open(cmd.Flag.Arg(0)); err == nil {
		r = ldap.NewReader(f)
		defer f.Close()
	} else {
		r = ldap.NewReader(os.Stdin)
	}
	for {
		cs, err := r.Read()
		switch err {
		case nil:
		case io.EOF:
			return nil
		default:
			return err
		}
		switch cs.ChangeType {
		default:
			return fmt.Errorf("unsupported change type: %s", cs.ChangeType)
		case ldap.ChangeAdd:
			err = c.Add(cs.Node, cs.Attrs)
		case ldap.ChangeModify:
			err = c.Modify(cs.Node, cs.Attrs)
		case ldap.ChangeDelete:
			err = c.Delete(cs.Node, false)
		}
		if err != nil {
			if !*skip {
				return err
			}
			log.Println(err)
		}
	}
	return nil
}

func Add(cmd *cli.Command, args []string) error {
	skip := cmd.Flag.Bool("c", false, "continuous operation mode")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	c, err := Client()
	if err != nil {
		return err
	}
	defer c.Unbind()

	var r *ldap.Reader
	if f, err := os.Open(cmd.Flag.Arg(0)); err == nil {
		r = ldap.NewReader(f)
		defer f.Close()
	} else {
		r = ldap.NewReader(os.Stdin)
	}
	for {
		cs, err := r.Read()
		switch err {
		case nil:
		case io.EOF:
			return nil
		default:
			return err
		}
		if err := c.Add(cs.Node, cs.Attrs); err != nil {
			if !*skip {
				return err
			}
			log.Println(err)
		}
	}
	return nil
}

func Rename(cmd *cli.Command, args []string) error {
	k := cmd.Flag.Bool("k", false, "keep rdn")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	c, err := Client()
	if err != nil {
		return err
	}
	defer c.Unbind()

	switch cmd.Flag.NArg() {
	case 2:
		return c.Rename(cmd.Flag.Arg(0), cmd.Flag.Arg(1), *k)
	case 3:
		return c.Move(cmd.Flag.Arg(0), cmd.Flag.Arg(1), cmd.Flag.Arg(2), *k)
	default:
		return fmt.Errorf("invalid number of arguments")
	}
}

func Delete(cmd *cli.Command, args []string) error {
	recurse := cmd.Flag.Bool("r", false, "recursive")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	c, err := Client()
	if err != nil {
		return err
	}
	defer c.Unbind()

	if err := c.Delete(cmd.Flag.Arg(0), *recurse); err != nil {
		return fmt.Errorf("%s: %s", err, cmd.Flag.Arg(0))
	}
	return nil
}
