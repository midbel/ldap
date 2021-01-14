package ldap

import (
	"fmt"
	"strings"

	"github.com/midbel/ber"
)

const (
	CtrlProxyAuthOID   = "2.16.840.1.113730.3.4.18"
	CtrlPaginateOID    = "1.2.840.113556.1.4.319"
	CtrlSortingOID     = "1.2.840.113556.1.4.473"
	CtrlAssertionOID   = "1.3.6.1.1.12"
	CtrlPreReadOID     = "1.3.6.1.1.13.1"
	CtrlPostReadOID    = "1.3.6.1.1.13.2"
	CtrlTransactionOID = "1.3.6.1.1.21.2"
)

var ControlNames = map[string]string{
	CtrlProxyAuthOID:   "proxied authorization control",
	CtrlPaginateOID:    "pagination control",
	CtrlSortingOID:     "sorting control",
	CtrlAssertionOID:   "assertion control",
	CtrlPreReadOID:     "pre read control",
	CtrlPostReadOID:    "post read control",
	CtrlTransactionOID: "transaction control",
}

type Control struct {
	OID      string `ber:"octetstr"`
	Critical bool
	Value    []byte `ber:"omitempty,octetstr"`
}

type ControlValue struct {
	OID   string
	Value interface{}
}

func (c *ControlValue) Unmarshal(b []byte) error {
	var (
		dec = ber.NewDecoder(b)
		raw []byte
		err error
	)
	c.OID, err = dec.DecodeString()
	if err != nil {
		return err
	}
	raw, err = dec.DecodeBytes()
	if err != nil {
		return err
	}
	dec.Reset(raw)
	switch c.OID {
	default:
		return fmt.Errorf("%s: unsupported control response", c.OID)
	case CtrlPaginateOID:
		var v PaginateValue
		err = dec.Decode(&v)
		if err == nil {
			c.Value = v
		}
	case CtrlPreReadOID, CtrlPostReadOID:
		var v Entry
		err = dec.Decode(&v)
		if err == nil {
			c.Value = v
		}
	}
	return err
}

func ProxyAuthorization(authid string) Control {
	return createControl(CtrlProxyAuthOID, []byte(authid), true)
}

type SortKey struct {
	Name    string `ber:"tag:0x4"`
	Rule    string `ber:"class:0x2,tag:0x0,omitempty"`
	Reverse bool   `ber:"class:0x2,tag:0x1"`
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
	return createControl(CtrlSortingOID, e.Bytes(), false)
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

	return createControl(CtrlPaginateOID, e.Bytes(), false)
}

func Assert(filter Filter) Control {
	var e ber.Encoder
	e.Encode(filter)
	return createControl(CtrlAssertionOID, e.Bytes(), true)
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
	return createControl(CtrlPreReadOID, e.Bytes(), false)
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
	return createControl(CtrlPostReadOID, e.Bytes(), false)
}

func createControl(oid string, value []byte, critical bool) Control {
	return Control{
		OID:      oid,
		Critical: critical,
		Value:    value,
	}
}
