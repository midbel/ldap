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
	fmt.Stringer
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

func (c compare) String() string {
	var str strings.Builder
	switch c.tag {
	default:
		str.WriteString("other")
	case tagFilterEquality:
		str.WriteString("eq")
	case tagFilterLesserEq:
		str.WriteString("le")
	case tagFilterGreaterEq:
		str.WriteString("ge")
	case tagFilterApprox:
		str.WriteString("approx")
	}
	str.WriteRune(lparen)
	str.WriteString(c.left)
	str.WriteRune(colon)
	str.WriteRune(space)
	str.WriteString(c.right)
	str.WriteRune(rparen)
	return str.String()
}

func (c compare) Marshal() ([]byte, error) {
	msg := struct {
		Attr  string `ber:"octetstr"`
		Value string `ber:"octetstr"`
	}{
		Attr:  c.left,
		Value: c.right,
	}
	var (
		e   ber.Encoder
		err error
		id  = ber.NewConstructed(c.tag).Context()
	)
	if err = e.EncodeWithIdent(msg, id); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
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

func (r relational) String() string {
	var str strings.Builder
	switch r.tag {
	case tagFilterAnd:
		str.WriteString("and")
	case tagFilterOr:
		str.WriteString("or")
	default:
		str.WriteString("other")
	}
	str.WriteRune(lparen)
	for i := range r.filters {
		if i > 0 {
			str.WriteString(", ")
		}
		str.WriteString(r.filters[i].String())
	}
	str.WriteRune(rparen)
	return str.String()
}

func (r relational) Marshal() ([]byte, error) {
	var (
		e   ber.Encoder
		err error
	)
	for _, f := range r.filters {
		if err = e.Encode(f); err != nil {
			return nil, err
		}
	}
	return e.As(ber.NewConstructed(r.tag).Context())
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

func (n not) String() string {
	return fmt.Sprintf("not(%s)", n.inner)
}

func (n not) Marshal() ([]byte, error) {
	var e ber.Encoder
	e.Encode(n.inner)
	return e.As(ber.NewConstructed(tagFilterNot).Context())
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

func (p present) String() string {
	return fmt.Sprintf("present(%s)", p.attr)
}

func (p present) Marshal() ([]byte, error) {
	var (
		e   ber.Encoder
		err error
		id  = ber.NewPrimitive(tagFilterPresent).Context()
	)
	if err = e.EncodeStringWithIdent(p.attr, id); err != nil {
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
	if len(values) == 0 {
		return s
	}
	n := len(values) - 1
	if values[0] != "" {
		s.pre = values[0]
	}
	values = values[1:]
	n--
	if n > 0 && values[n] != "" {
		s.post = values[n]
		values = values[:n]
	}
	s.any = append(s.any, values...)
	return s
}

func (s substring) String() string {
	return fmt.Sprintf("sub(%s, pre: %s, post: %s, any: %s)", s.attr, s.pre, s.post, s.any)
}

func (s substring) Marshal() ([]byte, error) {
	msg := struct {
		Attr   string `ber:"octetstr"`
		Values []ber.Marshaler
	}{
		Attr: s.attr,
	}
	msg.Values = append(msg.Values, createSubElem(s.pre, subInitial))
	for _, a := range s.any {
		msg.Values = append(msg.Values, createSubElem(a, subAny))
	}
	msg.Values = append(msg.Values, createSubElem(s.post, subFinal))

	var (
		e   ber.Encoder
		err error
		id  = ber.NewConstructed(tagFilterSubstrings).Context()
	)
	if err = e.EncodeWithIdent(msg, id); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

func (s substring) Not() Filter {
	return Not(s)
}

const (
	subInitial uint64 = iota
	subAny
	subFinal
)

type subElem struct {
	value string
	tag   uint64
}

func createSubElem(v string, tag uint64) ber.Marshaler {
	return subElem{
		value: v,
		tag:   tag,
	}
}

func (s subElem) Marshal() ([]byte, error) {
	if s.value == "" {
		return nil, nil
	}
	var (
		e   ber.Encoder
		err error
		id  = ber.NewPrimitive(s.tag).Context()
	)
	if err = e.EncodeStringWithIdent(s.value, id); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
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

func (e extensible) String() string {
	return fmt.Sprintf("%s(%s)", e.rule, e.attr)
}

func (e extensible) Marshal() ([]byte, error) {
	msg := struct {
		Rule  string `ber:"omitempty,class:0x2,tag:0x1"`
		Name  string `ber:"omitempty,class:0x2,tag:0x2"`
		Value string `ber:"class:0x2,tag:0x3"`
		DN    bool   `ber:"class:0x2,tag:0x4"`
	}{
		Rule:  e.rule,
		Name:  e.attr,
		Value: e.value,
		DN:    e.dn,
	}
	var (
		x   ber.Encoder
		err error
		id  = ber.NewConstructed(tagFilterExtensible).Context()
	)
	if err = x.EncodeWithIdent(msg, id); err != nil {
		return nil, err
	}
	return x.Bytes(), nil
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
		if str.Curr() == colon {
			r, _ = str.Next()
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
	attr, err := str.ScanUntil(accept, isOperator)
	if err == nil {
		str.Back()
		fp.Name = attr
	}
	return err
}

func (fp *filterParser) parseRule(str *scanner) error {
	accept := func(r rune) bool {
		return isDigit(r) || isLetter(r) || r == dot || r == minus
	}
	delim := func(r rune) bool {
		return r == colon
	}
	rule, err := str.ScanUntil(accept, delim)
	if err != nil {
		return err
	}
	if strings.ToLower(rule) != "dn" {
		fp.Rule = rule
		return nil
	}
	fp.DN = true
	if isOperator(str.Peek()) && str.Peek() != colon {
		return nil
	}
	fp.Rule, err = str.ScanUntil(accept, delim)
	return err
}

func (fp *filterParser) parseValue(str *scanner) error {
	accept := func(_ rune) bool {
		return true
	}
	delim := func(r rune) bool {
		return r == star || r == rparen
	}
	for {
		value, err := str.ScanUntil(accept, delim)
		if err != nil {
			return err
		}
		fp.Values = append(fp.Values, value)
		if str.Curr() == rparen {
			break
		}
	}
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
		filter = Substring(fp.Name, fp.Values)
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
	curr  int
	next  int
}

func scan(str string) *scanner {
	return &scanner{
		input: []byte(str),
	}
}

func (s *scanner) Back() {
	if s.curr == 0 {
		return
	}
	s.next = s.curr
	_, z := utf8.DecodeLastRune(s.input[:s.curr])
	s.curr -= z
}

func (s *scanner) Peek() rune {
	r, _ := utf8.DecodeRune(s.input[s.next:])
	return r
}

func (s *scanner) Curr() rune {
	if s.curr == 0 {
		return 0
	}
	r, _ := utf8.DecodeRune(s.input[s.curr:])
	return r
}

func (s *scanner) Next() (rune, error) {
	r, z := utf8.DecodeRune(s.input[s.next:])
	if r == utf8.RuneError {
		return 0, io.EOF
	}
	s.curr = s.next
	s.next += z
	return r, nil
}

func (s *scanner) ScanUntil(accept, delim func(rune) bool) (string, error) {
	var buf bytes.Buffer
	for {
		r, _ := s.Next()
		if delim(r) {
			break
		}
		if !accept(r) {
			return "", fmt.Errorf("scan: %w", illegalCharacter(r))
		}
		buf.WriteRune(r)
	}
	return buf.String(), nil
}

func (s *scanner) String() string {
	if s.curr >= len(s.input) {
		return ""
	}
	return string(s.input[s.curr:])
}

func invalidOperator(prev, curr rune) error {
	return fmt.Errorf("%w: %c%c", prev, curr)
}

func illegalCharacter(curr rune) error {
	return fmt.Errorf("%w: '%c' (%02[2]x)", ErrCharacter, curr)
}

func syntaxError(msg string) error {
	if msg == "" {
		return ErrSyntax
	}
	return fmt.Errorf("%w: %s", ErrSyntax, msg)
}
