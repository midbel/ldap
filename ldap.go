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
)

var codestrings = map[int]string{
	1:  "operation error",
	2:  "protocol error",
	3:  "time limit exeeded",
	4:  "size limit exeeded",
	7:  "authentication method not supported",
	8:  "stronger authentication required",
	11: "admin limit exeeded",
	12: "unavailable critical extension",
	13: "confidentialty required",
	16: "no such attribute",
	17: "undefined attribute type",
	18: "inappropriate matching",
	19: "constraint violation",
	20: "attribute or value exists",
	21: "invalid attribute syntax",
	32: "no such object",
	33: "alias problem",
	34: "invalid dn syntax",
	36: "alias dereferencing problem",
	48: "inappropriate authentication method",
	49: "invalid credentials",
	50: "insufficient access rights",
	51: "busy",
	52: "unavailable",
	53: "unwilling to perform",
	54: "loop detect",
	64: "naming violation",
	65: "objectclass violation",
	66: "not allowed on non leaf",
	67: "not allowed on rdn",
	68: "entry already exists",
	69: "objectclass mods prohibited",
	71: "affect multiple dsas",
	80: "other",
}

type Entry struct {
	Name  string
	Attrs []Attribute
}

type Result struct {
	Id         ber.Ident
	Code       int
	Name       string
	Diagnostic string
	Referals   []string
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
	str.WriteString(strconv.Itoa(r.Code))
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
	Value string
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
