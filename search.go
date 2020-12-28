package ldap

import (
	"time"
)

type Scope uint8

func (s Scope) isValid() bool {
	switch s {
	case ScopeBase, ScopeSingle, ScopeWhole:
		return true
	default:
		return false
	}
}

const (
	ScopeBase Scope = iota
	ScopeSingle
	ScopeWhole
)

type Deref uint8

func (d Deref) isValid() bool {
	switch d {
	case DerefNever, DerefSearching, DerefFinding, DerefAlways:
		return true
	default:
		return false
	}
}

const (
	DerefNever Deref = iota
	DerefSearching
	DerefFinding
	DerefAlways
)

type SearchRequest struct {
	base  string
	scope Scope
	deref Deref
	size  int
	delay int
	types bool
	attrs []string
}

func (sr SearchRequest) Marshal() ([]byte, error) {
	return nil, nil
}

type SearchOption func(*SearchRequest) error

func WithScope(scope Scope) SearchOption {
	return func(sr *SearchRequest) error {
		if !scope.isValid() {
			return nil
		}
		sr.scope = scope
		return nil
	}
}

func WithAttributes(attrs []string) SearchOption {
	return func(sr *SearchRequest) error {
		sr.attrs = append(sr.attrs, attrs...)
		return nil
	}
}

func WithLimit(limit int) SearchOption {
	return func(sr *SearchRequest) error {
		if limit >= 0 {
			sr.size = limit
		}
		return nil
	}
}

func WithTime(limit time.Duration) SearchOption {
	return func(sr *SearchRequest) error {
		sr.delay = int(limit.Seconds())
		return nil
	}
}

func WithTypes(only bool) SearchOption {
	return func(sr *SearchRequest) error {
		sr.types = only
		return nil
	}
}

func WithDeref(deref Deref) SearchOption {
	return func(sr *SearchRequest) error {
		if !deref.isValid() {
			return nil
		}
		sr.deref = deref
		return nil
	}
}
