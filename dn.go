package ldap

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

type DN struct {
	parts []RDN
}

func (d DN) String() string {
	parts := make([]string, len(d.parts))
	for i := range d.parts {
		parts[i] = d.parts[i].String()
	}
	return strings.Join(parts, ",")
}

func (d DN) Len() int {
	return len(d.parts)
}

func (d DN) Top() DN {
	return d.Parent(1)
}

func (d DN) Parent(i int) DN {
	if i >= len(d.parts) {
		return DN{}
	}
	return DN{parts: append([]RDN{}, d.parts[i:]...)}
}

func (d DN) RDN() RDN {
	return d.At(0)
}

func (d DN) At(i int) RDN {
	if len(d.parts) == 0 {
		return RDN{}
	}
	return d.parts[i]
}

type RDN struct {
	attrs []Attribute
}

func (r RDN) MultiValue() bool {
	return len(r.attrs) > 1
}

func (r RDN) String() string {
	var str strings.Builder
	for i, a := range r.attrs {
		if i > 0 {
			str.WriteRune(plus)
		}
		str.WriteString(a.Name)
		str.WriteRune(equal)
		str.WriteString(a.Values[0])
	}
	return str.String()
}

func Explode(dn string) (DN, error) {
	if !utf8.ValidString(dn) {
		return DN{}, fmt.Errorf("%s: not a valid DN", dn)
	}
	return explodeDN(strings.NewReader(dn))
}

func explodeDN(str *strings.Reader) (DN, error) {
	var dn DN
	for str.Len() > 0 {
		var rdn RDN
		for {
			var a Attribute
			if err := readAttrType(str, &a); err != nil {
				return dn, err
			}
			last, err := readAttrValue(str, &a)
			if err != nil {
				return dn, err
			}
			rdn.attrs = append(rdn.attrs, a)
			if last == 0 || last == comma {
				break
			}
		}
		dn.parts = append(dn.parts, rdn)
	}
	return dn, nil
}

func readAttrType(str *strings.Reader, a *Attribute) error {
	var (
		buf    strings.Builder
		accept func(rune) bool
	)
	switch r, _, _ := str.ReadRune(); {
	case isDigit(r):
		accept = acceptOID
	case isLetter(r):
		accept = acceptShortName
	default:
		return fmt.Errorf("unexpected character in attribute type")
	}
	str.UnreadRune()
	for {
		r, _, err := str.ReadRune()
		if err != nil {
			return err
		}
		if r == equal {
			break
		}
		if !accept(r) {
			return fmt.Errorf("unexpected character in attribute type")
		}
		buf.WriteRune(r)
	}
	a.Name = buf.String()
	return nil
}

func readAttrValue(str *strings.Reader, a *Attribute) (rune, error) {
	var (
		buf  strings.Builder
		last rune
	)
	for str.Len() > 0 {
		r, _, err := str.ReadRune()
		if err != nil && !errors.Is(err, io.EOF) {
			return r, err
		}
		if r == comma || r == plus {
			last = r
			break
		}
		buf.WriteRune(r)
	}
	a.Values = append(a.Values, buf.String())
	return last, nil
}

func isDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

func isLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func acceptOID(r rune) bool {
	return isDigit(r) || r == dot
}

func acceptShortName(r rune) bool {
	return isLetter(r) || r == minus
}
