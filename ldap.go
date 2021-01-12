package ldap

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/midbel/ber"
)

const RFC4511 = 3

const (
	Success                   = 0
	OperationError            = 1
	ProtocolError             = 2
	TimeExeeded               = 3
	SizeExeeded               = 4
	CompareFalse              = 5
	CompareTrue               = 6
	AuthMethNotSupport        = 7
	StrongerAuthRequired      = 8
	Referral                  = 10
	AdminLimitExeeded         = 11
	UnavailableCriticalExt    = 12
	ConfidentialtyRequired    = 13
	SaslBindInProgress        = 14
	NoSuchAttribute           = 16
	UndefinedAttributeType    = 17
	InappropriateMatching     = 18
	ConstraintViolation       = 19
	AttributeOrValueExists    = 20
	InvalidAttributeSyntax    = 21
	NoSuchObject              = 32
	AliasProblem              = 33
	InvalidDNSyntax           = 34
	AliasDerefProblem         = 36
	InappropriateAuthMeth     = 48
	InvalidCredentials        = 49
	InsufficientAccessRight   = 50
	Busy                      = 51
	Unavailable               = 52
	UnwillingToPerform        = 53
	LoopDetect                = 54
	NamingViolation           = 64
	ObjectClassViolation      = 65
	NotAllowedOnNonLeaf       = 66
	NotAllowedOnRdn           = 67
	EntryAlreadyExists        = 68
	ObjectClassModsProhibited = 69
	AffectMultipleDSA         = 71
	Other                     = 80
	Cancelled                 = 118
	NoSuchOperation           = 119
	TooLate                   = 120
	CannotCancel              = 121
	AssertionFailed           = 122
	ProxyAuthId               = 123
)

var codestrings = map[int64]string{
	OperationError:            "operation error",
	ProtocolError:             "protocol error",
	TimeExeeded:               "time limit exeeded",
	SizeExeeded:               "size limit exeeded",
	AuthMethNotSupport:        "authentication method not supported",
	StrongerAuthRequired:      "stronger authentication required",
	AdminLimitExeeded:         "admin limit exeeded",
	UnavailableCriticalExt:    "unavailable critical extension",
	ConfidentialityRequired:   "confidentialty required",
	NoSuchAttribute:           "no such attribute",
	UndefinedAttributeType:    "undefined attribute type",
	InappropriateMatching:     "inappropriate matching",
	ConstraintViolation:       "constraint violation",
	AttributeOrValueExists:    "attribute or value exists",
	InvalidAttributeSyntax:    "invalid attribute syntax",
	NoSuchObject:              "no such object",
	AliasProblem:              "alias problem",
	InvalidDNSyntax:           "invalid dn syntax",
	AliasDerefProblem:         "alias dereferencing problem",
	InappropriateAuthMeth:     "inappropriate authentication method",
	InvalidCredentials:        "invalid credentials",
	InsufficientAccessRight:   "insufficient access rights",
	Busy:                      "busy",
	Unavailable:               "unavailable",
	UnwillingToPerform:        "unwilling to perform",
	LoopDetect:                "loop detect",
	NamingViolation:           "naming violation",
	ObjectClassViolation:      "objectclass violation",
	NotAllowedOnNonLeaf:       "not allowed on non leaf",
	NotAllowedOnRdn:           "not allowed on rdn",
	EntryAlreadyExists:        "entry already exists",
	ObjectClassModsProhibited: "objectclass mods prohibited",
	AffectMultipleDSA:         "affect multiple dsas",
	Other:                     "other",
	Cancelled:                 "cancelled",
	NoSuchOperation:           "no such operation",
	TooLate:                   "too late",
	CannotCancel:              "cannot cancel",
	AssertionFailed:           "assertion failed",
	ProxyAuthId:               "proxy authorization identity refused",
}

type Entry struct {
	Name  string
	Attrs []Attribute
}

type Message struct {
	Id       uint32
	Body     interface{}
	Controls []Control `ber:"omitempty"`
}

type Result struct {
	Id         ber.Ident
	Code       int64
	Name       string
	Diagnostic string
	Referral   []string
}

func (r *Result) Unmarshal(b []byte) error {
	return unmarshalResult(ber.NewDecoder(b), r)
}

func (r Result) succeed() bool {
	switch r.Code {
	case Success, CompareTrue, CompareFalse, Referral, SaslBindInProgress:
		return true
	default:
		return false
	}
}

func (r Result) Error() string {
	var str strings.Builder
	str.WriteString(codestrings[r.Code])
	if r.Diagnostic != "" {
		str.WriteString(": ")
		str.WriteString(r.Diagnostic)
	}
	str.WriteString(" (")
	str.WriteString(strconv.FormatInt(r.Code, 10))
	str.WriteString(")")
	return str.String()
}

func unexpectedType(id ber.Ident) error {
	return fmt.Errorf("unexpected response type (class: %d, type: %d, tag: %d)", id.Class(), id.Type(), id.Tag())
}

type extendedRequest struct {
	OID  string      `ber:"class:0x2,tag:0x0"`
	Body interface{} `ber:"class:0x2,tag:0x1,omitempty"`
}

func createExtendedRequest(oid string, body interface{}) extendedRequest {
	e := extendedRequest{OID: oid}
	if body != nil {
		e.setBody(body)
	}
	return e
}

func (e *extendedRequest) setBody(msg interface{}) {
	e.Body = struct {
		Body interface{}
	}{
		Body: msg,
	}
}

type extendedResponse struct {
	Result
	Name  string
	Value []byte
}

func (e *extendedResponse) Unmarshal(b []byte) error {
	var (
		dec = ber.NewDecoder(b)
		err error
	)
	if err = unmarshalResult(dec, &e.Result); err != nil {
		return err
	}
	if id, err1 := dec.Peek(); err1 == nil && id.Tag() == 10 {
		e.Name, err = dec.DecodeString()
		if err != nil {
			return err
		}
	}
	if id, err1 := dec.Peek(); err1 == nil && id.Tag() == 11 {
		e.Value, err = dec.DecodeBytes()
		if err != nil {
			return err
		}
	}
	return nil
}

func unmarshalResult(d *ber.Decoder, r *Result) error {
	var err error
	if r.Code, err = d.DecodeInt(); err != nil {
		return err
	}
	if r.Name, err = d.DecodeString(); err != nil {
		return err
	}
	if r.Diagnostic, err = d.DecodeString(); err != nil {
		return err
	}
	if r.Code == Referral {
		err = d.Decode(&r.Referral)
	}
	return err
}

type Attribute struct {
	Name   string   `ber:"octetstr"`
	Values []string `ber:"set"`
}

func createAttribute(name, value string) Attribute {
	var values []string
	if value != "" {
		values = append(values, value)
	}
	return Attribute{
		Name:   name,
		Values: values,
	}
}

type AttributeAssertion struct {
	Desc string `ber:"tag:0x4"`
	Attr string `ber:"tag:0x4"`
}

func FromLDIF(ldif string) (AttributeAssertion, error) {
	var (
		ava AttributeAssertion
		x   = strings.Index(ldif, ":")
	)
	if x < 0 {
		return ava, fmt.Errorf("%s: invalid input string (missing colon)", ldif)
	}
	ava.Desc = ldif[:x]
	x++
	if ldif[x] == ':' {
		attr, err := base64.StdEncoding.DecodeString(ldif[x+1:])
		if err != nil {
			return ava, err
		}
		ava.Attr = string(attr)
	} else {
		ava.Attr = ldif[x:]
	}
	return ava, nil
}

func NewAssertion(attr, value string) AttributeAssertion {
	return AttributeAssertion{
		Desc: attr,
		Attr: value,
	}
}

const (
	equal     = '='
	comma     = ','
	dquote    = '"'
	backslash = '\\'
	plus      = '+'
	minus     = '-'
	star      = '*'
	dot       = '.'
	semicolon = ';'
	langle    = '<'
	rangle    = '>'
	sharp     = '#'
	newline   = '\n'
	carriage  = '\r'
	space     = ' '
	colon     = ':'
	ampersand = '&'
	pipe      = '|'
	lparen    = '('
	rparen    = ')'
	bang      = '!'
	tilde     = '~'
	null      = 0
)

func isDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

func isLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func isOperator(r rune) bool {
	switch r {
	case colon, equal, langle, rangle, tilde:
		return true
	default:
		return false
	}
}
