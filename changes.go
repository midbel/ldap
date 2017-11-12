package ldap

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	ErrInvalidSyntax = errors.New("invalid syntax")
	ErrSkip          = errors.New("skip")
)

const (
	ChangeAdd     = "add"
	ChangeDelete  = "delete"
	ChangeModify  = "modify"
	ChangeRDN     = "modrdn"
	ChangeReplace = "replace"
)

const (
	modifyAdd uint8 = iota
	modifyDel
	modifyRep
)

type Change struct {
	ChangeType string
	Node       string
	Attrs      []*Attr
}

type Attr struct {
	Op     uint8
	Name   string
	Values []string
}

type Reader struct {
	s *bufio.Scanner
}

func NewReader(r io.Reader) *Reader {
	s := bufio.NewScanner(r)
	s.Split(func(bs []byte, ateof bool) (int, []byte, error) {
		if ateof {
			return len(bs), bs, bufio.ErrFinalToken
		}
		ps := []byte("\n\n")
		ix := bytes.Index(bs, ps)
		if ix < 0 {
			return 0, nil, nil
		}
		vs := make([]byte, ix)
		copy(vs, bs[:ix])
		return ix + len(ps), bytes.TrimSpace(vs), nil
	})
	return &Reader{s}
}

func (r *Reader) Read() (*Change, error) {
	if !r.s.Scan() {
		return nil, io.EOF
	}
	s := bufio.NewScanner(bytes.NewReader(r.s.Bytes()))
	var vs []string
	for s.Scan() {
		x := s.Text()
		switch n := x[0]; {
		case n == '#':
		case n == ' ':
			i := len(vs) - 1
			vs[i] = vs[i] + strings.TrimSpace(x)
		default:
			vs = append(vs, x)
		}
	}
	if len(vs) == 0 {
		return nil, io.EOF
	}
	e := strings.NewReader(strings.Join(vs, "\n"))
	return readEntry(e)
}

func readEntry(r io.Reader) (*Change, error) {
	const version = "version"

	s := bufio.NewReader(r)
	if bs, err := s.Peek(len(version)); err == nil && string(bs) == version {
		s.ReadString('\n')
	}
	dn, err := readDN(s)
	if err != nil {
		return nil, err
	}
	ct, err := readChangeType(s)
	if err != nil && err != io.EOF {
		return nil, err
	}
	c := &Change{Node: dn, ChangeType: ct}
	switch ct {
	default:
		return nil, fmt.Errorf("not yet implemented %q", ct)
	case ChangeAdd:
		c.Attrs, err = readAdd(s)
	case ChangeModify:
		c.Attrs, err = readModify(s)
	case ChangeDelete:
		err = io.EOF
	}
	if err != nil && err != io.EOF {
		return nil, err
	}
	return c, nil
}

func readDN(r *bufio.Reader) (string, error) {
	a, v, err := readLine(r)
	if err != nil {
		return "", err
	}
	if a != "dn" {
		return "", ErrInvalidSyntax
	}
	return v, nil
}

func readChangeType(r *bufio.Reader) (string, error) {
	const changetype = "changetype"
	bs, err := r.Peek(len(changetype))
	if ct := string(bs); ct != changetype {
		return ChangeAdd, nil
	}
	_, v, err := readLine(r)
	if err != nil && err != io.EOF {
		return "", err
	}
	switch v {
	default:
		return "", fmt.Errorf("unsupported changetype %q", v)
	case ChangeAdd, ChangeModify, ChangeDelete:
		return v, nil
	}
}

func readLine(r *bufio.Reader) (string, string, error) {
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", "", err
	}
	ix := strings.IndexRune(line, ':')
	if ix < 0 {
		return "", "", ErrInvalidSyntax
	}
	return strings.TrimSpace(line[:ix]), strings.TrimSpace(line[ix+1:]), nil
}

func readAdd(r *bufio.Reader) ([]*Attr, error) {
	as := make(map[string]*Attr)
	for a, v, err := readLine(r); err == nil; a, v, err = readLine(r) {
		if _, ok := as[a]; !ok {
			as[a] = &Attr{Name: a}
		}
		as[a].Values = append(as[a].Values, v)
	}
	vs := make([]*Attr, 0, len(as))
	for _, a := range as {
		vs = append(vs, a)
	}
	return vs, nil
}

func readModify(r *bufio.Reader) ([]*Attr, error) {
	as := make([]*Attr, 0, 10)
	for a, v, err := readLine(r); err == nil; a, v, err = readLine(r) {
		var op uint8
		switch a {
		default:
			return nil, fmt.Errorf("unsupported change type %q", a)
		case ChangeAdd:
			op = modifyAdd
		case ChangeDelete:
			op = modifyDel
		case ChangeReplace:
			op = modifyRep
		}
		attr := &Attr{Op: op, Name: v}
		for a, v, err := readLine(r); err == nil; a, v, err = readLine(r) {
			if a != attr.Name {
				return nil, ErrInvalidSyntax
			}
			attr.Values = append(attr.Values, v)
		}
		as = append(as, attr)
	}
	return as, nil
}
