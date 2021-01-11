package ldap

import (
	"strings"

	"github.com/midbel/ber"
)

const (
	ctrlProxyAuthOID = "2.16.840.1.113730.3.4.18"
	ctrlPaginateOID  = "1.2.840.113556.1.4.319"
	ctrlSortingOID   = "1.2.840.113556.1.4.473"
	ctrlAssertionOID = "1.3.6.1.1.12"
	ctrlPreReadOID   = "1.3.6.1.1.13.1"
	ctrlPostReadOID  = "1.3.6.1.1.13.2"
)

type Control struct {
	OID      string `ber:"octetstr"`
	Critical bool
	Value    []byte `ber:"omitempty,octetstr"`
}

func ProxyAuthorization(authid string) Control {
	return createControl(ctrlProxyAuthOID, []byte(authid), true)
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
	return createControl(ctrlSortingOID, e.Bytes(), false)
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

	return createControl(ctrlPaginateOID, e.Bytes(), false)
}

func Assert(filter Filter) Control {
	var e ber.Encoder
	e.Encode(filter)
	return createControl(ctrlAssertionOID, e.Bytes(), true)
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
	return createControl(ctrlPreReadOID, e.Bytes(), false)
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
	return createControl(ctrlPostReadOID, e.Bytes(), false)
}

func createControl(oid string, value []byte, critical bool) Control {
	return Control{
		OID:      oid,
		Critical: critical,
		Value:    value,
	}
}
