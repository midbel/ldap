package ldap

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/midbel/ber"
)

var (
	ErrOperator  = errors.New("unknown operator")
	ErrCharacter = errors.New("illegal charater")
	ErrSyntax    = errors.New("bad syntax")
)

const (
	tagFilterAnd uint64 = iota
	tagFilterOr
	tagFilterNot
	tagFilterEquality
	tagFilterSubstrings
	tagFilterGreaterEq
	tagFilterLesserEq
	tagFilterPresent
	tagFilterApprox
	tagFilterExtensible
)

type Filter interface {
	Not() Filter
	ber.Marshaler
}

func ParseFilter(str string) (Filter, error) {
	if str == "" {
		return Present("objectClass"), nil
	}
	if !utf8.ValidString(str) {
		return nil, fmt.Errorf("%s: invalid utf8 string", str)
	}
	return parseFilter(scan(str))
}

type compare struct {
	left  string
	right string
	tag   uint64
}

func Equal(attr, value string) Filter {
	return createCompareFilter(attr, value, tagFilterEquality)
}

func LessEq(attr, value string) Filter {
	return createCompareFilter(attr, value, tagFilterLesserEq)
}

func GreatEq(attr, value string) Filter {
	return createCompareFilter(attr, value, tagFilterGreaterEq)
}

func Approx(attr, value string) Filter {
	return createCompareFilter(attr, value, tagFilterApprox)
}

func createCompareFilter(attr, value string, tag uint64) Filter {
	return compare{
		left:  attr,
		right: value,
		tag:   tag,
	}
}

func (c compare) Marshal() ([]byte, error) {
	return nil, nil
}

func (c compare) Not() Filter {
	return Not(c)
}

type relational struct {
	filters []Filter `ber:"set"`
	tag     uint64
}

func And(filters ...Filter) Filter {
	return relational{
		filters: filters,
		tag:     tagFilterAnd,
	}
}

func Or(filters ...Filter) Filter {
	return relational{
		filters: filters,
		tag:     tagFilterOr,
	}
}

func (r relational) Marshal() ([]byte, error) {
	return nil, nil
}

func (r relational) Not() Filter {
	return Not(r)
}

type not struct {
	inner Filter
}

func Not(f Filter) Filter {
	return not{f}
}

func (n not) Marshal() ([]byte, error) {
	return nil, nil
}

func (n not) Not() Filter {
	return n.inner
}

type present struct {
	attr string
}

func Present(attr string) Filter {
	return present{attr}
}

func (p present) Marshal() ([]byte, error) {
	var (
		e  ber.Encoder
		id = ber.NewPrimitive(tagFilterPresent).Context()
	)
	if err := e.EncodeStringWithIdent(p.attr, id); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

func (p present) Not() Filter {
	return Not(p)
}

type substring struct {
	attr string
	pre  string
	post string
	any  []string
}

func Substring(attr string, values []string) Filter {
	s := substring{
		attr: attr,
	}
	n := len(values) - 1
	if values[0] != "" {
		s.pre = values[0]
		values = values[1:]
		n--
	}
	if n > 0 && values[n] != "" {
		s.post = values[n]
		values = values[:n]
	}
	s.any = append(s.any, values...)
	return s
}

func (s substring) Marshal() ([]byte, error) {
	return nil, nil
}

func (s substring) Not() Filter {
	return Not(s)
}

type extensible struct {
	attr  string
	rule  string
	dn    bool
	value string
}

func ExtensibleMatch(attr, rule, value string, dn bool) Filter {
	return extensible{
		attr:  attr,
		rule:  rule,
		value: value,
		dn:    dn,
	}
}

func (e extensible) Marshal() ([]byte, error) {
	return nil, nil
}

func (e extensible) Not() Filter {
	return Not(e)
}

func parseFilter(str *scanner) (Filter, error) {
	r, err := str.Next()
	if err != nil {
		return nil, err
	}
	if r != lparen {
		return nil, syntaxError("parenthese expected")
	}
	if r, err = str.Next(); err != nil {
		return nil, err
	}
	var filter Filter
	switch r {
	case ampersand:
		all, err := parseList(str)
		if err != nil {
			return nil, err
		}
		filter = And(all...)
	case pipe:
		all, err := parseList(str)
		if err != nil {
			return nil, err
		}
		filter = Or(all...)
	case bang:
		not, err := parseFilter(str)
		if err != nil {
			return nil, err
		}
		filter = Not(not)
	case rparen:
	default:
		str.Back()
		return parseItem(str)
	}
	return filter, nil
}

func parseList(str *scanner) ([]Filter, error) {
	var all []Filter
	for {
		f, err := parseFilter(str)
		if err != nil {
			return nil, err
		}
		all = append(all, f)
		if r := str.Peek(); r == rparen {
			str.Next()
			break
		}
	}
	return all, nil
}

type filterParser struct {
	Type uint64

	Name string
	Rule string
	DN   bool

	Values []string
}

func parseItem(str *scanner) (Filter, error) {
	var fp filterParser
	return fp.Parse(str)
}

func (fp *filterParser) Parse(str *scanner) (Filter, error) {
	if err := fp.parseAttribute(str); err != nil {
		return nil, err
	}
	if fp.Type == tagFilterPresent {
		return fp.build()
	}
	if err := fp.parseValue(str); err != nil {
		return nil, err
	}
	return fp.build()
}

func (fp *filterParser) parseAttribute(str *scanner) error {
	if err := fp.parseAttr(str); err != nil {
		return err
	}

	r, err := str.Next()
	if err != nil {
		return err
	}
	if r == colon {
		if err := fp.parseRule(str); err != nil {
			return err
		}
		fp.Type = tagFilterExtensible
		if r, err = str.Next(); err != nil {
			return err
		}
	}
	switch r {
	case langle:
		if r, _ = str.Next(); r != equal {
			return invalidOperator(langle, r)
		}
		fp.Type = tagFilterLesserEq
	case rangle:
		if r, _ = str.Next(); r != equal {
			return invalidOperator(rangle, r)
		}
		fp.Type = tagFilterGreaterEq
	case equal:
		if fp.Type == tagFilterExtensible {
			break
		}
		fp.Type = tagFilterEquality

		if r, _ := str.Next(); r == star {
			if r = str.Peek(); r == rparen {
				str.Next()
				fp.Type = tagFilterPresent
				break
			}
		}
		str.Back()
	case tilde:
		if r, _ = str.Next(); r != equal {
			return invalidOperator(tilde, r)
		}
		fp.Type = tagFilterApprox
	default:
		return illegalCharacter(r)
	}
	return nil
}

func (fp *filterParser) parseAttr(str *scanner) error {
	accept := func(r rune) bool {
		return isDigit(r) || isLetter(r) || r == dot || r == minus
	}
	var buf bytes.Buffer
	for {
		r, err := str.Next()
		if err != nil {
			return err
		}
		if isOperator(r) {
			str.Back()
			break
		}
		if !accept(r) {
			return illegalCharacter(r)
		}
		buf.WriteRune(r)
	}
	fp.Name = buf.String()
	return nil
}

func (fp *filterParser) parseRule(str *scanner) error {
	accept := func(r rune) bool {
		return isDigit(r) || isLetter(r) || r == dot || r == minus
	}
	var buf bytes.Buffer
	for {
		r, err := str.Next()
		if err != nil {
			return err
		}
		if isOperator(r) {
			str.Back()
			break
		}
		if r == colon {
			if str := buf.String(); strings.ToLower(str) != "dn" {
				break
			}
			if fp.DN {
				return syntaxError("dn attribute already set")
			}
			fp.DN = true
			buf.Reset()
			continue
		}
		if !accept(r) {
			return illegalCharacter(r)
		}
		buf.WriteRune(r)
	}
	fp.Rule = buf.String()
	return nil
}

func (fp *filterParser) parseValue(str *scanner) error {
	var buf bytes.Buffer
	for {
		r, err := str.Next()
		if err != nil {
			return err
		}
		if r == rparen {
			break
		}
		if r == star {
			fp.Values = append(fp.Values, buf.String())
			buf.Reset()
			continue
		}
		if r == backslash {
			r, _ = str.Next()
		}
		buf.WriteRune(r)
	}
	fp.Values = append(fp.Values, buf.String())
	switch n := len(fp.Values); fp.Type {
	case tagFilterGreaterEq, tagFilterLesserEq, tagFilterApprox, tagFilterExtensible:
		if n > 1 {
			return syntaxError("")
		}
	case tagFilterEquality:
		if n > 1 {
			fp.Type = tagFilterSubstrings
		}
	}
	return nil
}

func (fp *filterParser) build() (Filter, error) {
	var filter Filter
	switch fp.Type {
	default:
		return nil, fmt.Errorf("unsupported filter type")
	case tagFilterEquality:
		filter = Equal(fp.Name, fp.Values[0])
	case tagFilterSubstrings:
		Substring(fp.Name, fp.Values)
	case tagFilterGreaterEq:
		filter = GreatEq(fp.Name, fp.Values[0])
	case tagFilterLesserEq:
		filter = LessEq(fp.Name, fp.Values[0])
	case tagFilterPresent:
		filter = Present(fp.Name)
	case tagFilterApprox:
		filter = Approx(fp.Name, fp.Values[0])
	case tagFilterExtensible:
		filter = ExtensibleMatch(fp.Name, fp.Rule, fp.Values[0], fp.DN)
	}
	return filter, nil
}

type scanner struct {
  input []byte
  ptr   int
}

func scan(str string) *scanner {
  return &scanner{
    input: []byte(str),
  }
}

func (s *scanner) Back() {
  if s.ptr == 0 {
    return
  }
  _, z := utf8.DecodeLastRune(s.input[:s.ptr])
  s.ptr -= z
}

func (s *scanner) Peek() rune {
  r, _ := utf8.DecodeRune(s.input[s.ptr:])
  return r
}

func (s *scanner) Curr() rune {
  if s.ptr == 0 {
    return 0
  }
  r, _ := utf8.DecodeLastRune(s.input[:s.ptr])
  return r
}

func (s *scanner) Next() (rune, error) {
  r, z := utf8.DecodeRune(s.input[s.ptr:])
  if r == utf8.RuneError {
    return 0, io.EOF
  }
  s.ptr += z
  return r, nil
}

func invalidOperator(prev, curr rune) error {
	return fmt.Errorf("%w: %c%c", prev, curr)
}

func illegalCharacter(curr rune) error {
	return fmt.Errorf("%w: %c (%O2[2]x)", ErrCharacter, curr)
}

func syntaxError(msg string) error {
	if msg == "" {
		return ErrSyntax
	}
	return fmt.Errorf("%w: %s", ErrSyntax, msg)
}
