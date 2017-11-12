package ldif

import (
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/midbel/ldap"
)

func PrintEntries(w io.Writer, es []*ldap.Entry) {
	for _, e := range es {
		PrintEntry(w, e)
	}
}

func PrintEntry(w io.Writer, e *ldap.Entry) {
	ps := strings.FieldsFunc(e.Node, func(r rune) bool {
		return r == ',' || r == '='
	})
	vs := make([]string, 0, len(ps)/2)
	for i := 1; i < len(ps); i += 2 {
		vs = append(vs, ps[i])
	}
	fmt.Fprintf(w, "# %s\n", strings.Join(vs, ", "))
	fmt.Fprintf(w, "dn: %s\n", e.Node)
	for a, vs := range e.Attrs {
		for _, v := range vs {
			if bs := []byte(v); utf8.Valid(bs) {
				fmt.Fprintf(w, "%s: %s\n", a, v)
			} else {
				fmt.Fprintf(w, "%s:: %s\n", a, base64.StdEncoding.EncodeToString(bs))
			}
		}
	}
	fmt.Fprintln(w)
}
