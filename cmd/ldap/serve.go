package main

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/midbel/cli"
	"github.com/midbel/ldap"
	"github.com/midbel/ldap/cmd/ldap/internal/ldif"
)

func Serve(cmd *cli.Command, args []string) error {
	site := cmd.Flag.String("s", "", "site")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	u, err := url.Parse(cmd.Flag.Arg(1))
	if err != nil {
		return err
	}
	var t *template.Template
	if i, err := os.Stat(*site); err == nil && i.IsDir() {
		fs := template.FuncMap{
			"join": strings.Join,
		}
		t = template.Must(template.New("site").Funcs(fs).ParseGlob(path.Join(*site, "*.html")))
	}

	http.Handle("/list/", &list{uri: u, tpl: t})
	return http.ListenAndServe(cmd.Flag.Arg(0), nil)
}

func AllowMethods(h http.Handler, ms ...string) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		ix := sort.SearchStrings(ms, r.Method)
		if ix < len(ms) && r.Method == ms[ix] {
			h.ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
	return http.HandlerFunc(f)
}

type list struct {
	uri *url.URL
	tpl *template.Template
}

func (l list) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	c, err := ldap.Bind(l.uri.Host, u, p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer c.Unbind()

	n := l.uri.Path
	if _, p := path.Split(r.URL.Path); p != "" {
		n = p
	}

	q := r.URL.Query()
	f, err := ldap.Parse(q.Get("filter"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	es, err := c.FindAll(n, f, ok)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var buf bytes.Buffer
	for _, a := range strings.Split(r.Header.Get("Accept"), ",") {
		switch a = strings.TrimSpace(a); {
		case a == "text/html" && l.tpl != nil:
			v := struct {
				Node    string
				Entries []*ldap.Entry
			}{
				Node:    n,
				Entries: es,
			}
			w.Header().Set("content-type", "text/html; charset: UTF-8")
			err := l.tpl.ExecuteTemplate(&buf, "list.html", v)
			if err != nil {
				log.Println(err)
			}
		case a == "application/directory" && l.tpl != nil:
			w.Header().Set("content-type", "application/ldif")
			ldif.PrintEntries(&buf, es)
		case a == "application/json":
			w.Header().Set("content-type", "application/json")
			json.NewEncoder(&buf).Encode(es)
		}
		if buf.Len() > 0 {
			if _, err := io.Copy(w, &buf); err != nil {
				log.Println(err)
			}
			return
		}
	}
	http.Error(w, "not accepted: "+r.Header.Get("Accept"), http.StatusNotAcceptable)
}
