package ldap

import (
	"fmt"

	"github.com/midbel/ber"
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

type compare struct {
	left  string
	right interface{}
	tag   uint64
}

func Equal(attr string, right interface{}) Filter {
	return nil
}

func LessEq(attr string, right interface{}) Filter {
	return nil
}

func GreatEq(attr string, right interface{}) Filter {
	return nil
}

func (c compare) Marshal() ([]byte, error) {
	return nil, nil
}

func (c compare) String() string {
	return ""
}

func (c compare) Not() Filter {
	return nil
}

type relational struct {
	filters []Filter
	tag     uint64
}

func And(filters ...Filter) Filter {
	return nil
}

func Or(filters ...Filter) Filter {
	return nil
}

func (r relational) Marshal() ([]byte, error) {
	return nil, nil
}

func (r relational) String() string {
	return ""
}

func (r relational) Not() Filter {
	return nil
}

type not struct {
	inner Filter
}

func (n not) Marshal() ([]byte, error) {
	return nil, nil
}

func (n not) String() string {
	return ""
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
	var e ber.Encoder
	if err := e.EncodeStringWithIdent(p.attr, ber.NewPrimitive(tagFilterPresent).Context()); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

func (p present) String() string {
	return fmt.Sprintf("%s=*", p.attr)
}

func (p present) Not() Filter {
	return nil
}
