package ldap

import (
	"fmt"
	"strings"

	"github.com/midbel/ber"
)

const (
	CtrlProxyAuthOID     = "2.16.840.1.113730.3.4.18"
	CtrlPaginateOID      = "1.2.840.113556.1.4.319"
	CtrlSortReqOID       = "1.2.840.113556.1.4.473"
	CtrlSortRespOID      = "1.2.840.113556.1.4.474"
	CtrlAssertionOID     = "1.3.6.1.1.12"
	CtrlPreReadOID       = "1.3.6.1.1.13.1"
	CtrlPostReadOID      = "1.3.6.1.1.13.2"
	CtrlTransactionOID   = "1.3.6.1.1.21.2"
	CtrlMatchedValuesOID = "1.2.826.0.1.3344810.2.3"
	CtrlDontUseCopyOID   = "1.3.6.1.1.22"
	CtrlManageDsaItOID   = "2.16.840.1.113730.3.4.2"
	CtrlSubentriesOID    = "1.3.6.1.4.1.4203.1.10.1"
)

var ControlNames = map[string]string{
	CtrlProxyAuthOID:     "proxied authorization control",
	CtrlPaginateOID:      "pagination control",
	CtrlSortReqOID:       "sort request control",
	CtrlSortRespOID:      "sort response control",
	CtrlAssertionOID:     "assertion control",
	CtrlPreReadOID:       "pre read control",
	CtrlPostReadOID:      "post read control",
	CtrlTransactionOID:   "transaction control",
	CtrlMatchedValuesOID: "matched values control",
	CtrlDontUseCopyOID:   "don't use copy control",
	CtrlManageDsaItOID:   "manage dsa it control",
	CtrlSubentriesOID:    "subentries control",
}

type Control struct {
	OID      string `ber:"octetstr"`
	Critical bool
	Value    []byte `ber:"omitempty,octetstr"`
}

type ControlValue struct {
	OID   string
	Value []byte
}

func (cv ControlValue) DecodeValue() (interface{}, error) {
	switch cv.OID {
	default:
		return cv.Value, nil
	case CtrlPaginateOID:
		var (
			p PaginateValue
			d  = ber.NewDecoder(cv.Value)
		)
		return p, d.Decode(&p)
	case CtrlPostReadOID, CtrlPreReadOID:
		var (
			e Entry
			d  = ber.NewDecoder(cv.Value)
		)
		return e, d.Decode(&e)
	}
}

func (cv ControlValue) AsEntry() (Entry, error) {
	v, err := cv.DecodeValue()
	if err != nil {
		return Entry{}, err
	}
	if e, ok := v.(Entry); ok {
		return e, nil
	}
	return Entry{}, fmt.Errorf("")
}

func (cv ControlValue) AsPaginate() (PaginateValue, error) {
	v, err := cv.DecodeValue()
	if err != nil {
		return PaginateValue{}, err
	}
	if p, ok := v.(PaginateValue); ok {
		return p, nil
	}
	return PaginateValue{}, fmt.Errorf("")
}

func ProxyAuthorization(authid string) Control {
	return CreateControl(CtrlProxyAuthOID, []byte(authid), true)
}

func FilterValues(filters []Filter) Control {
	var e ber.Encoder
	e.Encode(filters)
	return CreateControl(CtrlMatchedValuesOID, e.Bytes(), false)
}

type SortKey struct {
	Name    string `ber:"tag:0x4"`
	Rule    string `ber:"class:0x2,tag:0x0,omitempty"`
	Reverse bool   `ber:"class:0x2,tag:0x1,omitempty"`
}

func ParseSortKey(str string) SortKey {
	var (
		parts = strings.Split(str, ":")
		sk    SortKey
	)
	switch len(parts) {
	case 0:
	case 1:
		sk.Name = parts[0]
	case 2:
		sk.Name = parts[0]
		sk.Reverse = strings.ToLower(parts[1]) == "reverse"
	default:
		sk.Name = parts[0]
		sk.Rule = parts[1]
		sk.Reverse = strings.ToLower(parts[2]) == "reverse"
	}
	return sk
}

func Sort(keys ...SortKey) Control {
	var e ber.Encoder
	e.Encode(keys)
	return CreateControl(CtrlSortReqOID, e.Bytes(), false)
}

type PaginateValue struct {
	Size   int
	Cookie []byte
}

func Paginate(size int, cookie []byte) Control {
	msg := struct {
		Size   int
		Cookie []byte
	}{
		Size:   size,
		Cookie: cookie,
	}
	var e ber.Encoder
	e.Encode(msg)

	return CreateControl(CtrlPaginateOID, e.Bytes(), false)
}

func Assert(filter Filter) Control {
	var e ber.Encoder
	e.Encode(filter)
	return CreateControl(CtrlAssertionOID, e.Bytes(), true)
}

func PreRead(attrs []string) Control {
	var (
		e  ber.Encoder
		as [][]byte
	)
	for _, a := range attrs {
		as = append(as, []byte(a))
	}
	e.Encode(as)
	return CreateControl(CtrlPreReadOID, e.Bytes(), false)
}

func PostRead(attrs []string) Control {
	var (
		e  ber.Encoder
		as [][]byte
	)
	for _, a := range attrs {
		as = append(as, []byte(a))
	}
	e.Encode(as)
	return CreateControl(CtrlPostReadOID, e.Bytes(), false)
}

func CreateControl(oid string, value []byte, critical bool) Control {
	return Control{
		OID:      oid,
		Critical: critical,
		Value:    value,
	}
}
