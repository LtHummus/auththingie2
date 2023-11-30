package importer

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gurkankaymak/hocon"
	"github.com/rs/zerolog/log"

	"github.com/lthummus/auththingie2/rules"
	"github.com/lthummus/auththingie2/user"
)

type Results struct {
	Domain  string
	AuthURL string
	Rules   []rules.Rule
	Users   []user.User
}

func quoteTrim(s string) string {
	return strings.Trim(s, `"`)
}

func getString(o hocon.Object, key string) (*string, error) {
	v := o[key]
	if v == nil {
		return nil, nil
	}

	if v.Type() != hocon.StringType {
		return nil, fmt.Errorf("not a string: %s", key)
	}

	s := quoteTrim(v.(hocon.String).String())

	return &s, nil
}

func getBoolean(o hocon.Object, key string) (bool, error) {
	v := o[key]
	if v == nil {
		return false, nil
	}

	if v.Type() != hocon.BooleanType {
		return false, fmt.Errorf("not a boolean: %s", key)
	}

	return bool(v.(hocon.Boolean)), nil
}

func getStringArray(o hocon.Object, key string) ([]string, error) {
	v := o[key]
	if v == nil {
		return nil, nil
	}

	if v.Type() != hocon.ArrayType {
		return nil, fmt.Errorf("not an array: %s", key)
	}

	var res []string
	for _, curr := range v.(hocon.Array) {
		if curr.Type() != hocon.StringType {
			return nil, fmt.Errorf("not a string: %s", curr)
		}

		res = append(res, quoteTrim(string(curr.(hocon.String))))
	}

	return res, nil
}

func getDuration(o hocon.Object, key string) (*time.Duration, error) {
	v := o[key]
	if v == nil {
		return nil, nil
	}

	hdur, ok := v.(hocon.Duration)
	if !ok {
		return nil, fmt.Errorf("not a duration: %s: %T", key, v)
	}

	dur := time.Duration(hdur)

	return &dur, nil
}

func decodeUser(v hocon.Value) (*user.User, error) {
	obj, ok := v.(hocon.Object)
	if !ok {
		return nil, fmt.Errorf("could not convert to hocon.Object during user parsing. is %T", v)
	}

	htpasswdLine, err := getString(obj, "htpasswdLine")
	if err != nil {
		return nil, fmt.Errorf("could not deocde htpasswdLine: %w", err)
	}

	parts := strings.SplitN(*htpasswdLine, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("could not decode htpasswdLine: invalid format")
	}

	admin, err := getBoolean(obj, "admin")
	if err != nil {
		return nil, fmt.Errorf("could not deocde admin: %w", err)
	}

	totpSecret, err := getString(obj, "totpSecret")
	if err != nil {
		return nil, fmt.Errorf("could not decode totp line: %w", err)
	}

	roles, err := getStringArray(obj, "roles")
	if err != nil {
		return nil, fmt.Errorf("could not decode roles: %w", err)
	}

	return &user.User{
		Id:                uuid.New().String(),
		Username:          parts[0],
		PasswordHash:      parts[1],
		Roles:             roles,
		TOTPSeed:          totpSecret,
		Admin:             admin,
		PasswordTimestamp: time.Now().Unix(),
	}, nil
}

func decodeRule(v hocon.Value) (*rules.Rule, error) {
	obj, ok := v.(hocon.Object)
	if !ok {
		return nil, fmt.Errorf("could not convert to hocon.Object during rule parsing. is %T", v)
	}

	name, err := getString(obj, "name")
	if err != nil {
		return nil, fmt.Errorf("could not decode name: %w", err)
	}

	pp, err := getString(obj, "protocolPattern")
	if err != nil {
		return nil, fmt.Errorf("could not decode protocol pattern: %w", err)
	}

	hp, err := getString(obj, "hostPattern")
	if err != nil {
		return nil, fmt.Errorf("could not decode host pattern: %w", err)
	}

	pathP, err := getString(obj, "pathPattern")
	if err != nil {
		return nil, fmt.Errorf("could not decode path pattern: %w", err)
	}

	public, err := getBoolean(obj, "public")
	if err != nil {
		return nil, fmt.Errorf("could not decode public: %w", err)
	}

	roles, err := getStringArray(obj, "permittedRoles")
	if err != nil {
		return nil, fmt.Errorf("could not decode roles: %w", err)
	}

	timeout, err := getDuration(obj, "timeout")
	if err != nil {
		return nil, fmt.Errorf("could not decode timeout: %w", err)
	}

	return &rules.Rule{
		Name:            *name,
		ProtocolPattern: pp,
		HostPattern:     hp,
		PathPattern:     pathP,
		Public:          public,
		PermittedRoles:  roles,
		Timeout:         timeout,
	}, nil
}

func Import(contents string) (*Results, error) {
	cfg, err := hocon.ParseString(contents)
	if err != nil {
		log.Error().Err(err).Msg("could not parse imported config")
		return nil, err
	}

	c := &Results{
		Rules: make([]rules.Rule, 0),
	}

	ruleList := cfg.GetArray("auththingie.rules")

	for _, curr := range ruleList {
		obj, ok := curr.(hocon.Object)
		if !ok {
			log.Error().Msg("not valid hocon object in rules")
			return nil, fmt.Errorf("not a valid object. is %T", obj)
		}

		r, err := decodeRule(obj)
		if err != nil {
			log.Error().Interface("rule", obj).Err(err).Msg("could not parse rule")
			return nil, fmt.Errorf("could not parse rule")
		}

		c.Rules = append(c.Rules, *r)
	}

	userList := cfg.GetArray("auththingie.users")
	for _, curr := range userList {
		obj, ok := curr.(hocon.Object)
		if !ok {
			log.Error().Msg("not valid hocon object in users")
			return nil, fmt.Errorf("not a valid object. is %T", obj)
		}

		r, err := decodeUser(obj)
		if err != nil {
			log.Error().Err(err).Msg("could not parse user")
			return nil, fmt.Errorf("could not parse user")
		}

		c.Users = append(c.Users, *r)
	}

	c.Domain = quoteTrim(cfg.GetString("auththingie.domain"))
	c.AuthURL = quoteTrim(cfg.GetString("auththingie.authSiteUrl"))

	return c, nil
}
