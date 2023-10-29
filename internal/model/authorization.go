package model

import (
	"encoding/base64"
	"fmt"
	"strings"
)

func NewAuthorization() *Authorization {
	return &Authorization{}
}

type Authorization struct {
	parsed    bool
	scheme    AuthorizationScheme
	rawscheme string
	value     string
	basic     struct {
		username string
		password string
	}
}

func (a *Authorization) SchemeRaw() string {
	return a.rawscheme
}

func (a *Authorization) Scheme() AuthorizationScheme {
	return a.scheme
}

func (a *Authorization) Value() string {
	return a.value
}

func (a *Authorization) Basic() (username, password string) {
	if !a.parsed {
		return "", ""
	}

	switch a.scheme {
	case AuthorizationSchemeBasic:
		return a.basic.username, a.basic.password
	default:
		return "", ""
	}
}

func (a *Authorization) BasicUsername() (username string) {
	if !a.parsed {
		return ""
	}

	switch a.scheme {
	case AuthorizationSchemeBasic:
		return a.basic.username
	default:
		return ""
	}
}

func (a *Authorization) Parse(raw string) (err error) {
	a.parsed = true

	if len(raw) == 0 {
		a.scheme = AuthorizationSchemeNone

		return nil
	}

	a.scheme = AuthorizationSchemeInvalid

	scheme, value, found := strings.Cut(raw, " ")

	if !found {
		return fmt.Errorf("invalid scheme: the scheme is missing")
	}

	a.rawscheme = scheme
	a.value = value

	switch s := strings.ToLower(scheme); s {
	case "basic":
		a.scheme = AuthorizationSchemeBasic

		if err = a.parseSchemeBasic(); err != nil {
			return err
		}
	case "bearer":
		a.scheme = AuthorizationSchemeBearer
	default:
		return fmt.Errorf("invalid scheme: scheme with name '%s' is unknown", s)
	}

	return nil
}

func (a *Authorization) parseSchemeBasic() (err error) {
	var decoded []byte

	if decoded, err = base64.StdEncoding.DecodeString(a.value); err != nil {
		return fmt.Errorf("invalid value: failed to parse base64 basic scheme value: %w", err)
	}

	username, password, found := strings.Cut(string(decoded), ":")

	if !found {
		return fmt.Errorf("invalid value: failed to find the username password separator in the decoded basic scheme value")
	}

	if len(username) == 0 {
		return fmt.Errorf("invalid value: failed to find the username in the decoded basic value as it was empty")
	}

	if len(password) == 0 {
		return fmt.Errorf("invalid value: failed to find the password in the decoded basic value as it was empty")
	}

	a.basic.username, a.basic.password = username, password

	return nil
}

func (a *Authorization) ParseBytes(raw []byte) (err error) {
	return a.Parse(string(raw))
}

type AuthorizationScheme int

const (
	AuthorizationSchemeInvalid = iota - 1
	AuthorizationSchemeUnknown
	AuthorizationSchemeNone
	AuthorizationSchemeBasic
	AuthorizationSchemeBearer
)
