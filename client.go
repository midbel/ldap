package ldap

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/midbel/rustine/encoding/ber"
)

var (
	ErrUnsolicited = errors.New("unsolicited notification")
	ErrUnexpected  = errors.New("unexpected error")
)

const (
	star = "*"
	plus = "+"
)

const (
	tlsOID = "1.3.6.1.4.1.1466.20037"
	pwdOID = "1.3.6.1.4.1.4203.1.11.1"
)

const (
	Base uint8 = iota
	Single
	Whole
)

const (
	Never uint8 = iota
	Searching
	Finding
	Always
)

const (
	SearchResultEntry     = 0x04
	SearchResultReference = 0x06
)

const RFC4511 uint8 = 3

type Entry struct {
	Node  string
	Attrs map[string][]string
}

func (e Entry) MarshalJSON() ([]byte, error) {
	vs := make(map[string]interface{})
	vs["dn"] = e.Node
	for a := range e.Attrs {
		vs[a] = e.Attrs[a]
	}
	return json.Marshal(vs)
}

func (e Entry) MarshalXML(c *xml.Encoder, s xml.StartElement) error {
	return nil
}

type Result struct {
	Code        uint8
	Node        string
	Message     string
	Unsolicited bool `ber:"-"`
}

func (r *Result) Error() string {
	s, ok := statusText[int(r.Code)]
	if !ok {
		return fmt.Sprintf("unexpected (%d)", r.Code)
	}
	if len(r.Message) > 0 {
		return fmt.Sprintf("%s: %s", s, r.Message)
	}
	return s
}

type Client struct {
	mu   sync.Mutex
	curr uint32

	conn net.Conn
}

func Dial(addr string) (*Client, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Client{conn: c, curr: 1}, nil
}

func Bind(a, u, p string) (*Client, error) {
	c, err := Dial(a)
	if err != nil {
		return nil, err
	}
	if err := c.Bind(u, p); err != nil {
		c.conn.Close()
		return nil, err
	}
	return c, nil
}

func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return fmt.Errorf("close nil client")
	}
	return c.conn.Close()
}

func (c *Client) Bind(u, p string) error {
	c.mu.Lock()
	defer func() {
		c.curr++
		c.mu.Unlock()
	}()

	b := bind{RFC4511, u, p}
	if err := b.exec(c.conn, c.curr); err != nil {
		c.conn.Close()
		return err
	}
	return nil
}

func (c *Client) Unbind() error {
	c.mu.Lock()
	defer func() {
		c.curr++
		c.mu.Unlock()
	}()

	m := struct {
		Id uint32
		Op struct{} `ber:"application,simple,tag:2"`
	}{c.curr, struct{}{}}
	if err := ber.NewEncoder(c.conn).Encode(m); err != nil {
		return err
	}
	return c.conn.Close()
}

func (c *Client) FindAll(n string, f Filter, e bool) ([]*Entry, error) {
	attrs := []string{star}
	if e {
		attrs = append(attrs, plus)
	}
	return c.Filter(n, Whole, 0, f, attrs...)
}

func (c *Client) Find(n string, e bool) (*Entry, error) {
	attrs := []string{star}
	if e {
		attrs = append(attrs, plus)
	}
	es, err := c.Filter(n, Base, 1, nil, attrs...)
	if err != nil {
		return nil, err
	}
	if len(es) != 1 {
		return nil, ErrUnexpected
	}
	return es[0], nil
}

func (c *Client) Filter(b string, s uint8, n uint32, f Filter, attrs ...string) ([]*Entry, error) {
	c.mu.Lock()
	defer func() {
		c.curr++
		c.mu.Unlock()
	}()
	if f == nil {
		f = Present("objectClass")
	}
	q := query{
		Node:    b,
		Scope:   s,
		Alias:   Never,
		Limit:   n,
		Timeout: 0,
		Filter:  f,
		Only:    false,
		Attrs:   attrs,
	}
	return q.exec(c.conn, c.curr)
}

func (c *Client) Compare(n, a, v string) (bool, error) {
	c.mu.Lock()
	defer func() {
		c.curr++
		c.mu.Unlock()
	}()
	q := compare{
		Node: n,
		Ava:  Assert{Attr: a, Value: v},
	}
	return q.exec(c.conn, c.curr)
}

func (c *Client) Delete(n string, _ bool) error {
	c.mu.Lock()
	defer func() {
		c.curr++
		c.mu.Unlock()
	}()
	m := struct {
		Id uint32
		Op string `ber:"application,simple,tag:10"`
	}{c.curr, n}
	if err := ber.NewEncoder(c.conn).Encode(m); err != nil {
		return err
	}
	r, err := exec(c.conn)
	if err != nil {
		return err
	}
	if !isSuccess(int(r.Code)) {
		return r
	}
	return nil
}

func (c *Client) Rename(n, a string, k bool) error {
	c.mu.Lock()
	defer func() {
		c.curr++
		c.mu.Unlock()
	}()
	r := rename{
		Node: n,
		Name: a,
		Keep: k,
	}
	return r.exec(c.conn, c.curr)
}

func (c *Client) Move(n, a, s string, k bool) error {
	c.mu.Lock()
	defer func() {
		c.curr++
		c.mu.Unlock()
	}()
	m := move{
		Node:   n,
		Attr:   a,
		Keep:   k,
		Parent: s,
	}
	return m.exec(c.conn, c.curr)
}

func (c *Client) Add(n string, attrs []*Attr) error {
	c.mu.Lock()
	defer func() {
		c.curr++
		c.mu.Unlock()
	}()
	as := make([]attr, 0, len(attrs))
	for _, a := range attrs {
		if len(a.Values) == 0 {
			continue
		}
		as = append(as, attr{a.Name, a.Values})
	}
	a := add{Node: n, Attrs: as}
	return a.exec(c.conn, c.curr)
}

func (c *Client) Modify(n string, attrs []*Attr) error {
	c.mu.Lock()
	defer func() {
		c.curr++
		c.mu.Unlock()
	}()
	as := make([]change, 0, len(attrs))
	for _, a := range attrs {
		c := change{
			Id:   a.Op,
			Attr: attr{a.Name, a.Values},
		}
		as = append(as, c)
	}
	m := modify{Node: n, Changes: as}
	return m.exec(c.conn, c.curr)
}

func (c *Client) StartTLS(r bool) error {
	c.mu.Lock()
	defer func() {
		c.curr++
		c.mu.Unlock()
	}()
	s := startTLS{tlsOID}
	err := s.exec(c.conn, c.curr)
	if err == nil {
		return nil
	}
	if rs, ok := err.(*Result); ok && (!r && rs.Code == ProtocolError) {
		return nil
	}
	return err
}

func (c *Client) Abandon() error {
	c.mu.Lock()
	defer func() {
		c.curr++
		c.mu.Unlock()
	}()
	m := struct {
		Id uint32
		Op uint32 `ber:"application,simple,tag:16"`
	}{c.curr + 1, c.curr}
	if err := ber.NewEncoder(c.conn).Encode(m); err != nil {
		return err
	}
	return nil
}

func (c *Client) Passwd(u, p, n string) error {
	c.mu.Lock()
	defer func() {
		c.curr++
		c.mu.Unlock()
	}()
	w := passwd{u, p, n}
	return w.exec(c.conn, c.curr)
}

type passwd struct {
	Node string `ber:"context,optional,tag:0"`
	Old  string `ber:"context,optional,tag:1"`
	New  string `ber:"context,optional,tag:2"`
}

func (p passwd) exec(c net.Conn, id uint32) error {
	v := struct {
		Value passwd
	}{p}
	e := struct {
		Name  string `ber:"context,tag:0"`
		Value interface{} `ber:"context,tag:1"`
	}{pwdOID, v}
	m := struct {
		Id uint32
		Op interface{} `ber:"application,tag:23"`
	}{id, e}
	if err := ber.NewEncoder(c).Encode(m); err != nil {
		return err
	}
	r, err := exec(c)
	if err != nil {
		return err
	}
	if isSuccess(int(r.Code)) {
		return nil
	}
	return r
}

type startTLS struct {
	OID string `ber:"context,tag:0"`
}

func (s startTLS) exec(c net.Conn, id uint32) error {
	m := struct {
		Id uint32
		Op startTLS `ber:"application,tag:23"`
	}{id, s}
	if err := ber.NewEncoder(c).Encode(m); err != nil {
		return err
	}
	rs, err := exec(c)
	if err != nil {
		return err
	}
	if isSuccess(int(rs.Code)) {
		return nil
	}
	return rs
}

type change struct {
	Id   uint8 `ber:"tag:10"`
	Attr attr
}

type modify struct {
	Node    string
	Changes []change
}

func (m modify) exec(c net.Conn, id uint32) error {
	o := struct {
		Id uint32
		Op modify `ber:"application,tag:6"`
	}{id, m}
	if err := ber.NewEncoder(c).Encode(o); err != nil {
		return err
	}
	rs, err := exec(c)
	if err != nil {
		return err
	}
	if isSuccess(int(rs.Code)) {
		return nil
	}
	return rs
}

type add struct {
	Node  string
	Attrs []attr
}

func (a add) exec(c net.Conn, id uint32) error {
	m := struct {
		Id uint32
		Op add `ber:"application,tag:8"`
	}{id, a}
	if err := ber.NewEncoder(c).Encode(m); err != nil {
		return err
	}
	r, err := exec(c)
	if err != nil {
		return err
	}
	if isSuccess(int(r.Code)) {
		return nil
	}
	return r
}

type move struct {
	Node   string
	Attr   string
	Keep   bool
	Parent string `ber:"context,tag:0"`
}

func (m move) exec(c net.Conn, id uint32) error {
	o := struct {
		Id uint32
		Op move `ber:"application,tag:12"`
	}{id, m}
	if err := ber.NewEncoder(c).Encode(o); err != nil {
		return err
	}
	rs, err := exec(c)
	if err != nil {
		return err
	}
	if isSuccess(int(rs.Code)) {
		return nil
	}
	return rs
}

type rename struct {
	Node string
	Name string
	Keep bool
}

func (r rename) exec(c net.Conn, id uint32) error {
	m := struct {
		Id uint32
		Op rename `ber:"application,tag:12"`
	}{id, r}
	if err := ber.NewEncoder(c).Encode(m); err != nil {
		return err
	}
	rs, err := exec(c)
	if err != nil {
		return err
	}
	if isSuccess(int(rs.Code)) {
		return nil
	}
	return rs
}

type compare struct {
	Node string
	Ava  Assert
}

func (c compare) exec(cn net.Conn, id uint32) (bool, error) {
	m := struct {
		Id uint32
		Op compare `ber:"application,tag:14"`
	}{id, c}
	if err := ber.NewEncoder(cn).Encode(m); err != nil {
		return false, err
	}
	r, err := exec(cn)
	if err != nil {
		return false, err
	}
	switch r.Code {
	case CompareTrue:
		return true, nil
	case CompareFalse:
		return false, nil
	default:
		return false, r
	}
}

type query struct {
	Node    string
	Scope   uint8 `ber:"tag:10"`
	Alias   uint8 `ber:"tag:10"`
	Limit   uint32
	Timeout uint32
	Only    bool
	Filter  Filter
	Attrs   []string
}

func (q query) exec(c net.Conn, id uint32) ([]*Entry, error) {
	if q.Filter == nil {
		q.Filter = Present("objectClass")
	}
	m := struct {
		Id uint32
		Op query `ber:"application,tag:3"`
	}{id, q}
	if err := ber.NewEncoder(c).Encode(m); err != nil {
		return nil, err
	}
	d := ber.NewDecoder(c)

	var es []*Entry
	for {
		r := struct {
			Id uint32
			Op *raw
		}{Op: new(raw)}
		if err := d.Decode(&r); err != nil {
			return nil, err
		}
		if r.Id == 0 {
			return nil, ErrUnsolicited
		}
		switch v := r.Op.value.(type) {
		case *Result:
			if !isSuccess(int(v.Code)) {
				return nil, v
			}
			return es, nil
		case *Entry:
			es = append(es, v)
		default:
			return nil, ErrUnexpected
		}
	}
}

type bind struct {
	Version uint8
	User    string
	Passwd  string `ber:"context,tag:0"`
}

func (b bind) exec(c net.Conn, id uint32) error {
	m := struct {
		Id uint32
		Op bind `ber:"application,tag:0"`
	}{id, b}
	if err := ber.NewEncoder(c).Encode(m); err != nil {
		return err
	}
	r, err := exec(c)
	if err != nil {
		return err
	}
	if isSuccess(int(r.Code)) {
		return nil
	}
	return r
}

func exec(c net.Conn) (*Result, error) {
	r := struct {
		Id uint32
		Op *raw
	}{Op: new(raw)}
	if err := ber.NewDecoder(c).Decode(&r); err != nil {
		return nil, err
	}
	switch {
	// case r.Id == 0:
	// 	return nil, ErrUnsolicited
	case r.Op.value == nil:
		return nil, ErrUnexpected
	default:
		if s, ok := r.Op.value.(*Result); !ok {
			return nil, ErrUnexpected
		} else {
			return s, nil
		}
	}
}

type attr struct {
	Name   string
	Values []string `ber:"set"`
}

type raw struct {
	value interface{}
}

func (r *raw) UnmarshalBER(t byte, bs []byte) error {
	switch t & 0x1F {
	case SearchResultEntry:
		r.value = new(Entry)
	case SearchResultReference:
		return ber.Skip
	default:
		r.value = new(Result)
	}
	if r.value == nil {
		return ErrUnexpected
	}
	vs := []byte{t}
	vs = append(vs, ber.Length(bs)...)
	vs = append(vs, bs...)

	return ber.Unmarshal(vs, r.value)
}
