package ldap

import (
	"fmt"
	"net"
	"sync"

	"github.com/midbel/ber"
)

type Client struct {
	conn net.Conn

	mu        sync.Mutex
	msgid     uint32
	anonymous bool
}

func Anonymous(addr string) (*Client, error) {
	return Bind(addr, "", "")
}

func Bind(addr, user, passwd string) (*Client, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	client := Client{
		conn: c,
	}
	return &client, client.Bind(user, passwd)
}

func (c *Client) Bind(user, passwd string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.msgid++
	bind := struct {
		Version int
		Name    string `ber:"octetstr"`
		Pass    string `ber:"class:0x2,type:0x0,tag:0x0"`
	}{
		Version: RFC4511,
		Name:    user,
		Pass:    passwd,
	}

	var e ber.Encoder
	e.EncodeInt(int64(c.msgid))
	e.EncodeWithIdent(bind, ber.NewConstructed(bindRequest).Application())
	body, err := e.AsSequence()
	if err != nil {
		return fmt.Errorf("%w: encoding bind operation failed!", err)
	}
	return c.recv(body)
}

func (c *Client) Unbind() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.msgid++
	unbind := struct{}{}

	var e ber.Encoder
	e.EncodeInt(int64(c.msgid))
	e.EncodeWithIdent(unbind, ber.NewConstructed(unbindRequest).Application())
	body, err := e.AsSequence()
	if err != nil {
		return fmt.Errorf("%w: encoding unbind operation failed!", err)
	}

	if err := c.send(body); err != nil {
		return err
	}
	return c.conn.Close()
}

func (c *Client) Search(base string, options ...SearchOption) error {
	return nil
}

func (c *Client) Modify(cdn string) error {
	return nil
}

func (c *Client) Rename(cdn, ndn, pdn string, keep bool) error {
	return nil
}

func (c *Client) Move(cdn, ndn string, keep bool) error {
	return nil
}

func (c *Client) Add() error {
	return nil
}

func (c *Client) Delete() error {
	return nil
}

func (c *Client) Compare(dn string) error {
	return nil
}

func (c *Client) send(body []byte) error {
	_, err := c.conn.Write(body)
	return err
}

func (c *Client) recv(body []byte) error {
	if err := c.send(body); err != nil {
		return err
	}
	body = make([]byte, 4096)
	n, err := c.conn.Read(body)
	if err != nil {
		return err
	}
	res := struct {
		Id int
		Result
	}{}
	dec := ber.NewDecoder(body[:n])
	if err := dec.Decode(&res); err != nil {
		return fmt.Errorf("%w: decoding bind response failed!", err)
	}
	if res.succeed() {
		return nil
	}
	return res
}
