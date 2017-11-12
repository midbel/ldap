package ldap

import (
	"bytes"
	"fmt"
	"strings"
	"text/scanner"

	"github.com/midbel/rustine/ber"
)

const (
	TagFilterAnd byte = iota
	TagFilterOr
	TagFilterNot
	TagFilterEqual
	TagFilterSubstrings
	TagFilterGreater
	TagFilterLesser
	TagFilterPresent
	TagFilterApprox
)

//LDAP Filter supported operators
const (
	eq = "="
	ge = ">="
	le = "<="
	ae = "~="
)

//LDAP Filter supported symbols
const (
	amper    = '&'
	vertbar  = '|'
	exlam    = '!'
	lparen   = '('
	rparen   = ')'
	asterisk = '*'
)

type ParseError string

func (e ParseError) Error() string {
	return fmt.Sprintf("syntax error: unexpected token %q", string(e))
}

type Filter interface {
	Not() Filter
	fmt.Stringer
}

func Equal(a, v string) Filter {
	return Assert{eq, a, v}
}

func LesserOrEqual(a, v string) Filter {
	return Assert{le, a, v}
}

func GreaterOrEqual(a, v string) Filter {
	return Assert{ge, a, v}
}

func Parse(f string) (Filter, error) {
	if f == "" {
		return Present("objectClass"), nil
	}
	r := strings.NewReader(f)

	lex := new(scanner.Scanner)
	lex.Init(r)
	lex.Mode = scanner.ScanIdents | scanner.ScanChars | scanner.ScanFloats

	return parse(lex)
}

type Assert struct {
	op    string
	Attr  string
	Value interface{}
}

func (a Assert) MarshalBER() ([]byte, error) {
	v := struct {
		Attr  string
		Value string
	}{
		Attr:  a.Attr,
		Value: fmt.Sprint(a.Value),
	}
	bs, err := ber.Marshal(v)
	if err != nil {
		return nil, err
	}
	id := ber.ClassContext<<6 | ber.TypeCompound<<5
	switch a.op {
	case eq:
		id |= TagFilterEqual
	case ge:
		id |= TagFilterGreater
	case le:
		id |= TagFilterLesser
	default:
		return bs, nil
	}
	bs[0] = id
	return bs, nil
}

func (a Assert) Not() Filter {
	return not{a}
}

func (a Assert) String() string {
	return fmt.Sprintf("(%s%s%v)", a.Attr, a.op, a.Value)
}

type Substring struct {
	Attr   string
	Values []string
}

func (s Substring) Not() Filter {
	return not{s}
}

func (s Substring) String() string {
	return fmt.Sprintf("(%s=???)", s.Attr)
}

type Present string

func (p Present) MarshalBER() ([]byte, error) {
	bs, err := ber.Marshal(string(p))
	if err != nil {
		return nil, err
	}
	bs[0] = ber.ClassContext<<6 | ber.TypeSimple<<5 | TagFilterPresent
	return bs, nil
}

func (p Present) Not() Filter {
	return not{p}
}

func (p Present) String() string {
	return fmt.Sprintf("(%s=*)", string(p))
}

type and []Filter

func And(f ...Filter) Filter {
	return and(f)
}

func (a and) Not() Filter {
	return not{a}
}

func (a and) MarshalBER() ([]byte, error) {
	return marshalLogic(ber.ClassContext<<6|ber.TypeCompound<<5|TagFilterAnd, a...)
}

func (a and) String() string {
	parts := make([]string, 0, len(a))
	for _, f := range a {
		parts = append(parts, f.String())
	}
	return fmt.Sprintf("(%c%s)", amper, strings.Join(parts, ""))
}

type or []Filter

func Or(f ...Filter) Filter {
	return or(f)
}

func (o or) MarshalBER() ([]byte, error) {
	return marshalLogic(ber.ClassContext<<6|ber.TypeCompound<<5|TagFilterOr, o...)
}

func (o or) Not() Filter {
	return not{o}
}

func (o or) String() string {
	parts := make([]string, 0, len(o))
	for _, f := range o {
		parts = append(parts, f.String())
	}
	return fmt.Sprintf("(%c%s)", vertbar, strings.Join(parts, ""))
}

type not struct {
	Filter
}

func (n not) MarshalBER() ([]byte, error) {
	return marshalLogic(ber.ClassContext<<6|ber.TypeCompound<<5|TagFilterNot, n.Filter)
}

func (n not) String() string {
	return fmt.Sprintf("(%c%s)", exlam, n.Filter)
}

func marshalLogic(id byte, fs ...Filter) ([]byte, error) {
	var (
		vs  []byte
		buf bytes.Buffer
	)
	for _, f := range fs {
		bs, err := ber.Marshal(f)
		if err != nil {
			return nil, err
		}
		vs = append(vs, bs...)
	}

	buf.WriteByte(id)
	buf.Write(ber.Length(vs))
	buf.Write(vs)

	return buf.Bytes(), nil
}

func parse(lex *scanner.Scanner) (f Filter, err error) {
	token := lex.Scan()
	if token != lparen {
		return nil, ParseError(lex.TokenText())
	}
	token = lex.Scan()
	switch token {
	case amper:
		list := make([]Filter, 0)
		for {
			var other Filter
			other, err = parse(lex)
			list = append(list, other)
			if t := lex.Peek(); t == rparen {
				lex.Scan()
				break
			}
		}
		f = And(list...)
	case vertbar:
		list := make([]Filter, 0)
		for {
			var other Filter
			other, err = parse(lex)
			list = append(list, other)
			if t := lex.Peek(); t == rparen {
				lex.Scan()
				break
			}
		}
		f = Or(list...)
	case exlam:
		f, err = parse(lex)
		f = f.Not()
	case scanner.Ident:
		f, err = parseFilter(lex)
	case scanner.EOF:
		return
	default:
		err = ParseError(lex.TokenText())
	}
	return
}

func parseFilter(lex *scanner.Scanner) (Filter, error) {
	attr := lex.TokenText()

	var op string
	switch t := lex.Scan(); t {
	case '=':
		op = eq
	case '>':
		op = ge
		lex.Scan()
	case '<':
		op = le
		lex.Scan()
	case '~':
		op = ae
		lex.Scan()
	default:
		return nil, ParseError(op)
	}

	if t := lex.Peek(); t == rparen || t == asterisk {
		lex.Scan()
		return Present(attr), nil
	}

	var buf bytes.Buffer
	for {
		lex.Scan()
		buf.WriteString(lex.TokenText())
		if lex.Peek() == ' ' {
			buf.WriteString(" ")
		}
		if lex.Peek() == rparen {
			break
		}
	}
	if t := lex.Scan(); t != rparen {
		return nil, ParseError(lex.TokenText())
	}
	return Assert{op, attr, buf.String()}, nil
}
