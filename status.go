package ldap

const (
	Success            = 0
	CompareFalse       = 5
	CompareTrue        = 6
	Referral           = 10
	SaslBindInProgress = 14
)

const (
	OperationsError              = 1
	ProtocolError                = 2
	TimeLimitExceed              = 3
	SizeLimitExceed              = 4
	AuthMethodNotSupported       = 7
	StrongerAuthRequired         = 8
	AdminLimitExceeded           = 11
	UnavailableCriticalExtension = 12
	ConfidentialityRequired      = 13
	NoSuchAttribute              = 16
	UndefinedAttributeType       = 17
	InappropriateMatching        = 18
	ConstraintViolation          = 19
	AttributeOrValueExists       = 20
	InvalidAttributeSyntax       = 21
	NoSuchObject                 = 32
	AliasProblem                 = 33
	InvalidDNSyntax              = 34
	AliasDereferencingProblem    = 36
	InappropriateAuthentication  = 48
	InvalidCredentials           = 49
	InsufficientAccessRights     = 50
	Busy                         = 51
	Unavailable                  = 52
	UnwillingToPerform           = 53
	LoopDetect                   = 54
	NamingViolation              = 64
	ObjectClassViolation         = 65
	NotAllowedOnNonLeaf          = 66
	NotAllowedOnRDN              = 67
	EntryAlreadyExists           = 68
	ObjectClassModsProhibited    = 69
	AffectsMultipleDSAs          = 71
	Other                        = 80
)

var statusText = map[int]string{
	Success:              "operations succees",
	OperationsError:      "operations sequence invalid",
	ProtocolError:        "data not well formed/unsupported requested version",
	SizeLimitExceed:      "too many results to be returned",
	StrongerAuthRequired: "stronger authentication is required",
	CompareFalse:         "assertion successfully evaluted to false (or undefined)",
	CompareTrue:          "assertion successfully evaluted true",
	NoSuchObject:         "no such object",
	InvalidDNSyntax:      "invalid DN",
	Unavailable:          "server is shutting down or offline",
	UnwillingToPerform:   "server is unwilling to perform operation(s)",
	EntryAlreadyExists:   "entry already exists",
	Other:                "server error",
}

func isSuccess(c int) bool {
	switch c {
	case Success, CompareFalse, CompareTrue, Referral, SaslBindInProgress:
		return true
	default:
		return false
	}
}
