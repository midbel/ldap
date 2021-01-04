package ldap

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/midbel/ber"
)

const (
	oidStartTLS     = "1.3.6.1.4.1.1466.20037"
	oidChangePasswd = "1.3.6.1.4.1.4203.1.11.1"
)

type Client struct {
	conn net.Conn

	mu    sync.Mutex
	msgid uint32
}

func Open(addr string) (*Client, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	client := Client{
		conn: c,
	}
	return &client, nil
}

func BindTLS(addr, user, passwd string) (*Client, error) {
	c, err := Open(addr)
	if err != nil {
		return nil, err
	}
	if err := c.StartTLS(); err != nil {
		return nil, err
	}
	return c, c.Bind(user, passwd)
}

func Bind(addr, user, passwd string) (*Client, error) {
	c, err := Open(addr)
	if err != nil {
		return nil, err
	}
	return c, c.Bind(user, passwd)
}

func (c *Client) Bind(user, passwd string) error {
	msg := struct {
		Version int
		Name    string `ber:"octetstr"`
		Pass    string `ber:"class:0x2,type:0x0,tag:0x0"`
	}{
		Version: RFC4511,
		Name:    user,
		Pass:    passwd,
	}
	return c.execute(msg, ldapBindRequest)
}

func (c *Client) Unbind() error {
	defer c.conn.Close()
	msg := struct{}{}
	return c.execute(msg, ldapUnbindRequest)
}

func (c *Client) Search(base string, options ...SearchOption) ([]Entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.msgid++

	search := searchRequest{
		Base:   base,
		Scope:  ScopeBase,
		Deref:  DerefNever,
		Filter: Present("objectClass"),
	}
	for _, opt := range options {
		if err := opt(&search); err != nil {
			return nil, err
		}
	}

	var e ber.Encoder
	e.EncodeInt(int64(c.msgid))
	e.EncodeWithIdent(search, ber.NewConstructed(ldapSearchRequest).Application())
	body, err := e.AsSequence()
	if err != nil {
		return nil, err
	}
	return c.search(body)
}

func (c *Client) Modify(dn string, attrs []PartialAttribute) error {
	msg := struct {
		Name  string `ber:"octetstr"`
		Attrs []PartialAttribute
	}{
		Name:  dn,
		Attrs: attrs,
	}
	return c.execute(msg, ldapModifyRequest)
}

func (c *Client) Add(dn string, attrs []Attribute) error {
	msg := struct {
		Name  string `ber:"octetstr"`
		Attrs []Attribute
	}{
		Name:  dn,
		Attrs: attrs,
	}
	return c.execute(msg, ldapAddRequest)
}

func (c *Client) Delete(dn string) error {
	return c.execute([]byte(dn), ldapDelRequest)
}

func (c *Client) ModifyPassword(dn, curr, next string) error {
	msg := struct {
		Name string `ber:"class:0x2,tag:0x0,omitempty"`
		Old  string `ber:"class:0x2,tag:0x1,omitempty"`
		New  string `ber:"class:0x2,tag:0x2,omitempty"`
	}{
		Name: dn,
		Old:  curr,
		New:  next,
	}
	req := createExtendedRequest(oidChangePasswd, msg)
	return c.execute(req, ldapExtendedRequest)
}

func (c *Client) StartTLS() error {
	req := createExtendedRequest(oidStartTLS, nil)
	err := c.execute(req, ldapExtendedRequest)
	if err == nil {
		cfg := tls.Config{
			InsecureSkipVerify: true,
		}
		c.conn = tls.Client(c.conn, &cfg)
	}
	return err
}

func (c *Client) Rename(dn, rdn string, keep bool) error {
	msg := struct {
		Name  string `ber:"octetstr"`
		Value string `ber:"octetstr"`
		Keep  bool
	}{
		Name:  dn,
		Value: rdn,
		Keep:  keep,
	}
	return c.execute(msg, ldapModDNRequest)
}

func (c *Client) Move(dn, parent string) error {
	name, err := Explode(dn)
	if err != nil {
		return err
	}
	msg := struct {
		Name   string `ber:"octetstr"`
		Value  string `ber:"octetstr"`
		Keep   bool
		Parent string `ber:"octetstr"`
	}{
		Name:   dn,
		Value:  name.RDN().String(),
		Keep:   false,
		Parent: parent,
	}
	return c.execute(msg, ldapModDNRequest)
}

func (c *Client) Compare(dn string, ava AttributeAssertion) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.msgid++

	cmp := struct {
		Name string `ber:"octetstr"`
		Ava  AttributeAssertion
	}{
		Name: dn,
		Ava:  ava,
	}

	var e ber.Encoder
	e.EncodeInt(int64(c.msgid))
	e.EncodeWithIdent(cmp, ber.NewConstructed(ldapCmpRequest).Application())
	body, err := e.AsSequence()
	if err != nil {
		return false, err
	}
	res, err := c.result(body, ldapCmpResponse)
	return res.Code == CompareTrue, err
}

func (c *Client) execute(msg interface{}, app uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.msgid++

	var id ber.Ident
	switch app {
	case ldapUnbindRequest, ldapDelRequest:
		id = ber.NewPrimitive(app)
	default:
		id = ber.NewConstructed(app)
	}

	var e ber.Encoder
	e.EncodeInt(int64(c.msgid))
	e.EncodeWithIdent(msg, id.Application())
	body, err := e.AsSequence()
	if err != nil {
		return err
	}

	switch app {
	default:
		app = 0
	case ldapBindRequest:
		app = ldapBindResponse
	case ldapAddRequest:
		app = ldapAddResponse
	case ldapModifyRequest:
		app = ldapModifyResponse
	case ldapDelRequest:
		app = ldapDelResponse
	case ldapModDNRequest:
		app = ldapModDNResponse
	case ldapExtendedRequest:
		app = ldapExtendedResponse
	}
	_, err = c.result(body, app)
	return err
}

func (c *Client) result(body []byte, app uint64) (Result, error) {
	if _, err := c.conn.Write(body); err != nil {
		return Result{}, err
	}
	if app == 0 {
		return Result{}, nil
	}
	body = make([]byte, 1<<15)
	n, err := c.conn.Read(body)
	if err != nil {
		return Result{}, err
	}
	res := struct {
		Id int
		Result
	}{}
	dec := ber.NewDecoder(body[:n])
	if err := dec.Decode(&res); err != nil {
		return res.Result, fmt.Errorf("%w: decoding response failed!", err)
	}
	if res.succeed() {
		return res.Result, nil
	}
	return res.Result, res.Result
}

func (c *Client) search(body []byte) ([]Entry, error) {
	if _, err := c.conn.Write(body); err != nil {
		return nil, err
	}
	body = make([]byte, 1<<15)
	var (
		es   []Entry
		res  Result
		done bool
		dec  = ber.NewDecoder(nil)
	)
	for !done {
		n, err := c.conn.Read(body)
		if err != nil {
			return nil, err
		}
		dec.Append(body[:n])
		for dec.Can() && !done {
			var msg searchMessage
			if err := dec.Decode(&msg); err != nil {
				return nil, err
			}
			id, _ := msg.Body.Peek()
			switch tag := id.Tag(); uint64(tag) {
			case ldapSearchResDone:
				if err := msg.Decode(&res); err != nil {
					return nil, err
				}
				done = true
			case ldapSearchResEntry:
				var e Entry
				if err := msg.Decode(&e); err != nil {
					return nil, err
				}
				es = append(es, e)
			case ldapSearchResRef:
			default:
				return nil, fmt.Errorf("unexpected response code (%02x)!", tag)
			}
		}
	}
	if !res.succeed() {
		return nil, res
	}
	return es, nil
}

type searchMessage struct {
	Id   int
	Body ber.Raw
}

func (sm searchMessage) Empty() bool {
	return len(sm.Body) == 0
}

func (sm searchMessage) Decode(val interface{}) error {
	d := ber.NewDecoder([]byte(sm.Body))
	return d.Decode(val)
}
