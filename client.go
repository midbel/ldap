package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/midbel/ber"
)

const (
	oidStartTLS     = "1.3.6.1.4.1.1466.20037"
	oidChangePasswd = "1.3.6.1.4.1.4203.1.11.1"
	oidWhoami       = "1.3.6.1.4.1.4203.1.11.3"
	oidCancel       = "1.3.6.1.1.8"
	oidBeginTx      = "1.3.6.1.1.21.1"
	oidEndTx        = "1.3.6.1.1.21.3"
)

var ExtensionNames = map[string]string{
	oidStartTLS:     "Start TLS extension",
	oidChangePasswd: "Modifiy password extension",
	oidWhoami:       "Who am I extension",
	oidCancel:       "Cancel extension",
	oidBeginTx:      "Begin Transaction extension",
	oidEndTx:        "End Transaction",
}

const (
	noticeDisconnect = "1.3.6.1.4.1.1466.20036"
	noticeAbortedTx  = "1.3.6.1.1.21.4"
)

var ErrUnsolicited = errors.New("unsolicited notification")

const (
	ldapBindRequest      uint64 = 0
	ldapBindResponse            = 1
	ldapUnbindRequest           = 2
	ldapSearchRequest           = 3
	ldapSearchResEntry          = 4
	ldapSearchResDone           = 5
	ldapSearchResRef            = 19
	ldapModifyRequest           = 6
	ldapModifyResponse          = 7
	ldapAddRequest              = 8
	ldapAddResponse             = 9
	ldapDelRequest              = 10
	ldapDelResponse             = 11
	ldapModDNRequest            = 12
	ldapModDNResponse           = 13
	ldapCmpRequest              = 14
	ldapCmpResponse             = 15
	ldapAbandonRequest          = 16
	ldapExtendedRequest         = 23
	ldapExtendedResponse        = 24
)

type Client struct {
	conn net.Conn

	mu     sync.Mutex
	msgid  uint32
	binded bool

	tx []byte
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

func BindTLS(addr, user, passwd string, cfg *tls.Config) (*Client, error) {
	c, err := Open(addr)
	if err != nil {
		return nil, err
	}
	if err := c.StartTLS(cfg); err != nil {
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

func (c *Client) Begin() error {
	if len(c.tx) > 0 {
		return fmt.Errorf("transaction already running")
	}
	req := createExtendedRequest(oidBeginTx, nil)
	res, err := c.executeExtended(req, nil)
	if err == nil {
		c.tx = res.Value
	}
	return err
}

func (c *Client) Commit() error {
	if len(c.tx) == 0 {
		return fmt.Errorf("no running transaction")
	}
	msg := struct {
		Commit bool
		Id     []byte
	}{
		Commit: true,
		Id:     c.tx,
	}
	var e ber.Encoder
	e.Encode(msg)
	body, err := e.AsSequence()
	if err != nil {
		return err
	}

	req := createExtendedRequest(oidEndTx, body)
	_, err = c.executeExtended(req, nil)
	if err == nil {
		c.tx = c.tx[:0]
	}
	return err
}

func (c *Client) Rollback() error {
	if len(c.tx) == 0 {
		return fmt.Errorf("no running transaction")
	}
	msg := struct {
		Commit bool
		Id     []byte
	}{
		Commit: false,
		Id:     c.tx,
	}
	var e ber.Encoder
	e.Encode(msg)
	body, err := e.AsSequence()
	if err != nil {
		return err
	}

	req := createExtendedRequest(oidEndTx, body)
	_, err = c.executeExtended(req, nil)
	if err == nil {
		c.tx = c.tx[:0]
	}
	return err
}

func (c *Client) Bind(user, passwd string, controls ...Control) error {
	if c.binded {
		return nil
	}
	msg := struct {
		Version int
		Name    string `ber:"octetstr"`
		Pass    string `ber:"class:0x2,type:0x0,tag:0x0"`
	}{
		Version: RFC4511,
		Name:    user,
		Pass:    passwd,
	}
	err := c.execute(msg, ldapBindRequest, controls)
	if err == nil {
		c.binded = true
	}
	return err
}

func (c *Client) Unbind(controls ...Control) error {
	defer c.conn.Close()
	if !c.binded {
		return nil
	}
	msg := struct{}{}
	return c.execute(msg, ldapUnbindRequest, controls)
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
	if cs := search.controls; len(cs) > 0 {
		e.EncodeWithIdent(cs, ber.NewConstructed(0).Context())
	}
	body, err := e.AsSequence()
	if err != nil {
		return nil, err
	}
	return c.executeSearch(body)
}

func (c *Client) Whoami(controls ...Control) (string, error) {
	req := createExtendedRequest(oidWhoami, nil)
	res, err := c.executeExtended(req, controls)
	if err != nil {
		return "", err
	}
	return string(res.Value), nil
}

func (c *Client) Modify(dn string, attrs []PartialAttribute, controls ...Control) error {
	msg := struct {
		Name  string `ber:"octetstr"`
		Attrs []PartialAttribute
	}{
		Name:  dn,
		Attrs: attrs,
	}
	return c.execute(msg, ldapModifyRequest, controls)
}

func (c *Client) Add(dn string, attrs []Attribute, controls ...Control) error {
	msg := struct {
		Name  string `ber:"octetstr"`
		Attrs []Attribute
	}{
		Name:  dn,
		Attrs: attrs,
	}
	return c.execute(msg, ldapAddRequest, controls)
}

func (c *Client) Delete(dn string, controls ...Control) error {
	return c.execute([]byte(dn), ldapDelRequest, controls)
}

func (c *Client) ModifyPassword(dn, curr, next string, controls ...Control) error {
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
	return c.execute(req, ldapExtendedRequest, controls)
}

func (c *Client) StartTLS(cfg *tls.Config, controls ...Control) error {
	if _, ok := c.conn.(*tls.Conn); ok {
		return nil
	}
	req := createExtendedRequest(oidStartTLS, nil)
	_, err := c.executeExtended(req, controls)
	if err == nil {
		c.conn = tls.Client(c.conn, cfg)
	}
	return err
}

func (c *Client) Rename(dn, rdn string, keep bool, controls ...Control) error {
	msg := struct {
		Name  string `ber:"octetstr"`
		Value string `ber:"octetstr"`
		Keep  bool
	}{
		Name:  dn,
		Value: rdn,
		Keep:  keep,
	}
	return c.execute(msg, ldapModDNRequest, controls)
}

func (c *Client) Move(dn, parent string, controls ...Control) error {
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
	return c.execute(msg, ldapModDNRequest, controls)
}

func (c *Client) Compare(dn string, ava AttributeAssertion, controls ...Control) (bool, error) {
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
	if len(controls) > 0 {
		e.EncodeWithIdent(controls, ber.NewConstructed(0).Context())
	}
	body, err := e.AsSequence()
	if err != nil {
		return false, err
	}
	res, err := c.result(body, ldapCmpResponse)
	return res.Code == CompareTrue, err
}

func (c *Client) Abandon(msgid int, controls ...Control) error {
	return nil
}

func (c *Client) Cancel(msgid int, controls ...Control) error {
	return nil
}

func (c *Client) executeExtended(msg interface{}, controls []Control) (extendedResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.msgid++

	var e ber.Encoder
	e.EncodeInt(int64(c.msgid))
	e.EncodeWithIdent(msg, ber.NewConstructed(ldapExtendedRequest).Application())
	if len(controls) > 0 {
		e.EncodeWithIdent(controls, ber.NewConstructed(0).Context())
	}
	body, err := e.AsSequence()
	if err != nil {
		return extendedResponse{}, err
	}

	return c.extendedResult(body)
}

func (c *Client) withTransaction(app uint64) (Control, bool) {
	if len(c.tx) == 0 {
		return Control{}, false
	}
	switch app {
	case ldapAddRequest, ldapModifyRequest, ldapDelRequest, ldapModDNRequest:
	default:
		return Control{}, false
	}
	return createControl(CtrlTransactionOID, c.tx, true), true
}

func (c *Client) execute(msg interface{}, app uint64, controls []Control) error {
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

	if ctrl, ok := c.withTransaction(app); ok {
		controls = append(controls, ctrl)
	}

	var e ber.Encoder
	e.EncodeInt(int64(c.msgid))
	e.EncodeWithIdent(msg, id.Application())
	if len(controls) > 0 {
		e.EncodeWithIdent(controls, ber.NewConstructed(0).Context())
	}
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
	}
	_, err = c.result(body, app)
	return err
}

func (c *Client) extendedResult(body []byte) (extendedResponse, error) {
	var res extendedResponse
	if _, err := c.conn.Write(body); err != nil {
		return res, err
	}

	body = make([]byte, 1<<15)
	n, err := c.conn.Read(body)
	if err != nil {
		return res, err
	}

	var (
		msg rawMessage
		dec = ber.NewDecoder(body[:n])
	)
	if err := dec.Decode(&msg); err != nil {
		return res, err
	}
	if err := msg.Decode(&res); err != nil {
		return res, err
	}
	if res.succeed() {
		return res, nil
	}
	return res, res.Result
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
	var (
		res Result
		msg rawMessage
		dec = ber.NewDecoder(body[:n])
	)
	if err := dec.Decode(&msg); err != nil {
		return res, err
	}
	if err := msg.Decode(&res); err != nil {
		return res, err
	}
	if res.succeed() {
		return res, nil
	}
	return res, res
}

func (c *Client) executeSearch(body []byte) ([]Entry, error) {
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
			var msg rawMessage
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

type rawMessage struct {
	Id       int
	Body     ber.Raw
	Controls []ControlValue
}

func (r rawMessage) Empty() bool {
	return len(r.Body) == 0
}

func (r rawMessage) Decode(val interface{}) error {
	d := ber.NewDecoder([]byte(r.Body))
	if r.Id == 0 {
		var e extendedResponse
		if err := d.Decode(&e); err != nil {
			return err
		}
		switch e.Name {
		case noticeDisconnect:
			return fmt.Errorf("%w: disconnection", ErrUnsolicited)
		case noticeAbortedTx:
			return fmt.Errorf("%w: transaction aborted", ErrUnsolicited)
		default:
			return e.Result
		}
	}
	return d.Decode(val)
}
