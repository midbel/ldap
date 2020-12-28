package ldap

import (
	"strconv"
	"strings"
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

const (
	bindRequest int = iota
	bindResponse
	unbindRequest
	searchRequest
	searchResEntry
	searchResDone
	searchResRef
	modifyRequest
	modifyResponse
	addRequest
	addResponse
	delRequest
	delResponse
	modDNRequest
	modDNResponse
	cmpRequest
	cmpResponse
	abandonRequest
	extendedRequest
	extendedResponse
)

type Control struct {
	oid      string
	critical bool
	value    string
}

type Result struct {
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

type AttributeAssertion struct {
	desc string
	attr []byte
}

func NewAssertion(attr, value string) AttributeAssertion {
	return AttributeAssertion{
		desc: attr,
		attr: []byte(value),
	}
}
