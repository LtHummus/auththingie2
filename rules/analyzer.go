package rules

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/lthummus/auththingie2/config"
)

const (
	updateDebounceTime = 100 * time.Millisecond
)

type Analyzer interface {
	MatchesRule(ri *RequestInfo) *Rule
	Rules() []Rule
	Errors() []string
	KnownRoles() []string
	AddRule(r Rule)
	WriteConfig() error
}

var (
	ruleFieldOrder = []string{"name",
		"source",
		"protocol_pattern",
		"host_pattern",
		"path_pattern",
		"timeout",
		"public",
		"permitted_roles"}
)

type ViperConfigAnalyzer struct {
	lock       sync.RWMutex
	rules      []Rule
	errors     []string
	knownRoles []string

	lastUpdate time.Time
}

var _ Analyzer = (*ViperConfigAnalyzer)(nil)

// ruleConverter exists because I want to override the default order that fields get serialized in a rule. By default,
// the serializer will put the fields in lexicographical order, but I don't like that because it makes sense to go name
// first, then protocol then host, then path since that's the order components appear in an address. So we build a
// yaml.MapSlice which supports specifying an order for serialization. In fact, everything in this file below this point
// is in service of this bit of polish
func ruleConverter(r map[string]any) yaml.MapSlice {
	ms := &yaml.MapSlice{}

	for _, key := range ruleFieldOrder {
		if x := r[key]; x != nil {
			*ms = append(*ms, yaml.MapItem{
				Key:   key,
				Value: r[key],
			})
		}
	}

	return *ms
}

func NewFromConfig() (*ViperConfigAnalyzer, error) {
	a := &ViperConfigAnalyzer{}
	viper.OnConfigChange(func(in fsnotify.Event) {
		log.Info().Msg("detected config file change")
		err := a.UpdateFromConfigFile()
		if err != nil {
			log.Warn().Err(err).Msg("error reading rules from config file")
		}
	})
	err := a.UpdateFromConfigFile()
	return a, err
}

func (a *ViperConfigAnalyzer) UpdateFromConfigFile() error {
	a.lock.Lock()
	defer a.lock.Unlock()

	if time.Since(a.lastUpdate) < updateDebounceTime {
		log.Debug().Dur("time_since_update", time.Since(a.lastUpdate)).Msg("updated too quickly, ignoring")
		return nil
	}

	var rules []rawRule

	a.errors = nil

	err := viper.UnmarshalKey("Rules", &rules)
	if err != nil {
		log.Error().Err(err).Msg("could not unmarshal Rules")
		a.errors = []string{fmt.Sprintf("could not load rules configuration: %s", err.Error())}
		return err
	}

	knownRoleSet := map[string]bool{}
	var ruleNames []string

	a.rules = nil
	parsedRules := make([]Rule, len(rules))
	for i, curr := range rules {
		r, err := curr.ToRule()
		if err != nil {
			a.errors = append(a.errors, fmt.Sprintf("could not parse rule: %s", err.Error()))
		} else {
			parsedRules[i] = *r
			ruleNames = append(ruleNames, r.Name)
			for _, curr := range r.PermittedRoles {
				knownRoleSet[curr] = true
			}
		}
	}

	a.knownRoles = make([]string, 0)
	for curr := range knownRoleSet {
		a.knownRoles = append(a.knownRoles, curr)
	}

	log.Info().Strs("loaded_rules", ruleNames).Strs("known_roles", a.knownRoles).Strs("errors", a.errors).Msg("loaded rules from files")

	a.rules = parsedRules

	if a.errors != nil {
		return errors.New("there was an error parsing the rules")
	}

	a.lastUpdate = time.Now()
	return nil
}

func (a *ViperConfigAnalyzer) WriteConfig() error {
	// here, we take our rules from the struct directly and serialize them here. We do that because viper.Set will actually
	// force the rules we have in to an override map inside Viper which we can not access. This means that when the
	// filesystem notification comes through of the config file update, we'll never ever actually reload rules from
	// the config file because of that override. What we'll do instead is serialize the rules specifically HERE and then
	// pass them in to the writer, so we avoid the override map entirely
	//
	// and the reason we do THIS instead of just having viper serialize everything is because viper's serializer will
	// write the fields in lexicographical order which we do not want for rules since they make sense to write in
	// protocol, host, path order because that's how they will be read by a human (and a machine, for that matter)
	serializedRules := make([]yaml.MapSlice, len(a.rules))
	for i := range a.rules {
		serializedRules[i] = ruleConverter(a.rules[i].toSerializableMap())
	}
	err := config.WriteCurrentConfigState(config.WriteOverride{
		Key:   "rules",
		Value: serializedRules,
	})
	if err != nil {
		log.Warn().Err(err).Msg("could not write config file")
		return err
	}

	log.Info().Msg("saved config file")
	return nil
}

func (a *ViperConfigAnalyzer) MatchesRule(ri *RequestInfo) *Rule {
	a.lock.RLock()
	defer a.lock.RUnlock()
	for _, curr := range a.rules {
		if curr.Matches(ri) {
			return &curr
		}
	}

	return nil
}

func (a *ViperConfigAnalyzer) AddRule(r Rule) {
	a.rules = append(a.rules, r)
}

func (a *ViperConfigAnalyzer) Rules() []Rule {
	a.lock.RLock()
	defer a.lock.RUnlock()

	ret := make([]Rule, len(a.rules))
	copied := copy(ret, a.rules)
	log.Debug().Int("num_copied", copied).Msg("copied rules")
	return ret
}

func (a *ViperConfigAnalyzer) KnownRoles() []string {
	ret := make([]string, len(a.knownRoles))
	copy(ret, a.knownRoles)
	return ret
}

func (a *ViperConfigAnalyzer) Errors() []string {
	return a.errors
}
