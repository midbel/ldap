package ldap

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ChangeType int

const (
	ModAdd ChangeType = iota
	ModDelete
	ModReplace
)

type PartialAttribute struct {
	Mod ChangeType
	Attribute
}

func createPartial(name string) PartialAttribute {
	return createPartialWithValue(name, "")
}

func createPartialWithValue(name, value string) PartialAttribute {
	return PartialAttribute{
		Attribute: createAttribute(name, value),
	}
}

type Change struct {
	Name  string
	Attrs []PartialAttribute
}

func ReadLDIF(r io.Reader, exec func(ChangeType, Change) error) error {
  rs := bufio.NewReader(r)
	return readBlock(rs, func() error {
		var c Change
		ct, err := parseChange(rs, &c)
		if err != nil && !errors.Is(err, eob) {
			return err
		}
		return exec(ct, c)
	})
}

const (
	ldifDN     = "dn"
	ldifChange = "changetype"
	ldifAdd    = "add"
	ldifDel    = "delete"
	ldifMod    = "modify"
	ldifRep    = "replace"
)

func parseChange(rs *bufio.Reader, cg *Change) (ChangeType, error) {
	name, value, err := readAttribute(rs)
	if err != nil {
		return 0, err
	}
	if name != ldifDN {
		return 0, fmt.Errorf("dn attribute not provided")
	}
	cg.Name = value
	if name, value, err = readAttribute(rs); err != nil {
		return 0, err
	}
	var (
		parse  func(*bufio.Reader, *Change) error
		action ChangeType
	)
	if name == ldifChange {
		switch value {
		case ldifAdd:
			parse, action = parseAdd, ModAdd
		case ldifDel:
			parse, action = parseDelete, ModDelete
		case ldifMod:
			parse, action = parseModify, ModReplace
		default:
			return 0, fmt.Errorf("%s: unsupported value %s", name, value)
		}
	} else {
		cg.Attrs = append(cg.Attrs, createPartialWithValue(name, value))
		parse, action = parseAdd, ModAdd
	}
	return action, parse(rs, cg)
}

func parseModify(rs *bufio.Reader, cg *Change) error {
	return readBlock(rs, func() error {
		name, value, err := readAttribute(rs)
		if err != nil {
			return err
		}
		pa := createPartial(value)
		switch name {
		case ldifAdd:
			pa.Mod = ModAdd
		case ldifDel:
			pa.Mod = ModDelete
		case ldifRep:
			pa.Mod = ModReplace
		default:
			return fmt.Errorf("%s: unknown operation", name)
		}
		err = readBlock(rs, func() error {
			name, value, err := readAttribute(rs)
			if err != nil {
				return err
			}
			if name != pa.Name {
				return fmt.Errorf("%s: expected %s", name, pa.Name)
			}
			pa.Values = append(pa.Values, value)
			return nil
		})
		if err == nil || errors.Is(err, eob) {
			cg.Attrs = append(cg.Attrs, pa)
		}
		return err
	})
}

func parseAdd(rs *bufio.Reader, cg *Change) error {
	return readBlock(rs, func() error {
		name, value, err := readAttribute(rs)
		if err != nil {
			return err
		}

		x := sort.Search(len(cg.Attrs), func(i int) bool {
			return cg.Attrs[i].Name <= name
		})

		attr := createPartialWithValue(name, value)
		if x < len(cg.Attrs) && cg.Attrs[x].Name == name {
			cg.Attrs[x].Values = append(cg.Attrs[x].Values, value)
		} else if x < len(cg.Attrs) {
			attrs := append([]PartialAttribute{attr}, cg.Attrs[x:]...)
			cg.Attrs = append(cg.Attrs[:x], attrs...)
		} else {
			cg.Attrs = append(cg.Attrs, attr)
		}
		return nil
	})
}

var eob = errors.New("end of block")

func readBlock(rs *bufio.Reader, exec func() error) error {
	for {
		b, err := rs.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		switch b {
		case sharp:
			skipComments(rs)
		case carriage, newline:
			skipBlanks(b, rs)
			return eob
		case minus:
			b, _ := rs.ReadByte()
			if b == carriage || b == newline {
				rs.ReadString(newline)
				return eob
			}
			return fmt.Errorf("dash")
		default:
			rs.UnreadByte()
			if err := exec(); err != nil && !errors.Is(err, eob) {
				return err
			}
		}
	}
	return nil
}

func parseDelete(rs *bufio.Reader, cg *Change) error {
	b, err := rs.ReadByte()
	if err != nil {
		if errors.Is(err, io.EOF) {
			err = nil
		}
		return err
	}
	if b == carriage || b == newline {
		return skipBlanks(b, rs)
	}
	return fmt.Errorf("delete block should be empty")
}

func readAttribute(rs *bufio.Reader) (string, string, error) {
	b, err := rs.ReadByte()
	if err != nil {
		return "", "", err
	}
	if b == minus {
		_, err = rs.ReadString(newline)
		return "", "", err
	} else {
		rs.UnreadByte()
	}
	name, err := readDescriptor(rs)
	if err != nil {
		return "", "", err
	}
	value, err := readValue(rs)
	if err != nil {
		return "", "", err
	}
	return name, value, nil
}

func readDescriptor(rs *bufio.Reader) (string, error) {
	name, err := rs.ReadString(colon)
	if err != nil {
		err = fmt.Errorf("%w: colon not found", err)
	}
	return strings.TrimSuffix(name, string(colon)), err
}

func readValue(rs *bufio.Reader) (string, error) {
	b, err := rs.ReadByte()
	if err != nil {
		return "", err
	}
	var value string
	switch b {
	case colon:
		lines, err := readLines(rs)
		if err != nil {
			return "", err
		}
		value = strings.Join(lines, "")
	case langle:
		value, err = readFromURL(rs)
	default:
		rs.UnreadByte()
		lines, err := readLines(rs)
		if err != nil {
			return "", err
		}
		value = strings.Join(lines, "")
	}
	return value, err
}

const (
	schemeFile  = "file"
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

func readFromURL(rs *bufio.Reader) (string, error) {
	str, err := rs.ReadString(newline)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(strings.TrimSpace(str))
	if err != nil {
		return "", err
	}
	var value string
	switch strings.ToLower(u.Scheme) {
	case schemeHTTP, schemeHTTPS:
		value, err = readFromHTTP(u.String())
	case schemeFile:
		value, err = readFromFile(u.Path)
	default:
		err = fmt.Errorf("%s: unsupported scheme", u.Scheme)
	}
	return value, err
}

func readFromFile(file string) (string, error) {
	var files []string
	if cwd, err := os.Getwd(); err == nil {
		files = append(files, filepath.Join(cwd, file))
	}
	files = append(files, file)
	for _, file := range files {
		buf, err := ioutil.ReadFile(file)
		if err == nil {
			return base64.StdEncoding.EncodeToString(buf), nil
		}
	}
	return "", fmt.Errorf("%s: not found", file)
}

func readFromHTTP(file string) (string, error) {
	resp, err := http.Get(file)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func skipBlanks(b byte, rs *bufio.Reader) error {
	for {
		if b == carriage {
			rs.ReadByte()
		}
		b, err := rs.ReadByte()
		if err != nil {
			break
		}
		if b != carriage && b != newline {
			rs.UnreadByte()
			break
		}
	}
	return nil
}

func skipComments(rs *bufio.Reader) error {
	rs.ReadString(newline)
	for {
		b, err := rs.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		if b != sharp {
			rs.UnreadByte()
			break
		}
		rs.ReadString(newline)
	}
	return nil
}

func readLines(rs *bufio.Reader) ([]string, error) {
	var (
		str, _ = rs.ReadString(newline)
		lines  []string
	)
	lines = append(lines, strings.TrimSpace(str))
	for {
		b, err := rs.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if b != space {
			rs.UnreadByte()
			break
		}
		str, _ := rs.ReadString(newline)
		lines = append(lines, strings.TrimSuffix(str, "\r\n"))
	}
	return lines, nil
}
