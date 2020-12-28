package ldap

import (
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
	ber.Marshaler
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
