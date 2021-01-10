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

type searchRequest struct {
	Base   string `ber:"tag:0x4"`
	Scope  Scope  `ber:"tag:0xa"`
	Deref  Deref  `ber:"tag:0xa"`
	Size   int
	Delay  int
	Types  bool
	Filter Filter
	Attrs  [][]byte
	controls []Control `ber:"-"`
}

type SearchOption func(*searchRequest) error

func WithControl(ctrl Control) SearchOption {
	return func(sr *searchRequest) error {
		sr.controls = append(sr.controls, ctrl)
		return nil
	}
}

func WithFilter(filter Filter) SearchOption {
	return func(sr *searchRequest) error {
		sr.Filter = filter
		return nil
	}
}

func WithScope(scope Scope) SearchOption {
	return func(sr *searchRequest) error {
		if !scope.isValid() {
			return nil
		}
		sr.Scope = scope
		return nil
	}
}

func WithAttributes(attrs []string) SearchOption {
	return func(sr *searchRequest) error {
		for _, a := range attrs {
			if len(a) == 0 {
				continue
			}
			sr.Attrs = append(sr.Attrs, []byte(a))
		}
		return nil
	}
}

func WithLimit(limit int) SearchOption {
	return func(sr *searchRequest) error {
		if limit >= 0 {
			sr.Size = limit
		}
		return nil
	}
}

func WithTime(limit time.Duration) SearchOption {
	return func(sr *searchRequest) error {
		sr.Delay = int(limit.Seconds())
		return nil
	}
}

func WithTypes(only bool) SearchOption {
	return func(sr *searchRequest) error {
		sr.Types = only
		return nil
	}
}

func WithDeref(deref Deref) SearchOption {
	return func(sr *searchRequest) error {
		if !deref.isValid() {
			return nil
		}
		sr.Deref = deref
		return nil
	}
}
