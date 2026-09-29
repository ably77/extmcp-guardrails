// Package policy loads the guardrail policy that the ExtMCP server enforces.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

const (
	ModeAuthz  = "authz"
	ModeRedact = "redact"
)

type Config struct {
	Mode          string             `yaml:"mode"`
	Personas      map[string]Persona `yaml:"personas"`
	DisabledTools []string           `yaml:"disabledTools"`
	Email         Email              `yaml:"email"`
	Approval      Approval           `yaml:"approval"`
	Patterns      []Pattern          `yaml:"patterns"`
}

type Persona struct {
	Tools   []string `yaml:"tools"`
	POLimit float64  `yaml:"poLimit"`
}

type Email struct {
	AllowedDomains []string `yaml:"allowedDomains"`
}

type Approval struct {
	URL string `yaml:"url"`
}

type Pattern struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
	re    *regexp.Regexp
}

// Re returns the compiled pattern. Parse fills it in.
func (p Pattern) Re() *regexp.Regexp { return p.re }

// Parse decodes and validates a policy. Unknown keys are errors, so a typo
// such as "polimit" fails loudly instead of silently zeroing a limit.
func Parse(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	switch c.Mode {
	case ModeAuthz:
		if len(c.Personas) == 0 {
			return nil, errors.New("authz mode needs at least one persona")
		}
	case ModeRedact:
		if len(c.Patterns) == 0 {
			return nil, errors.New("redact mode needs at least one pattern")
		}
		for i := range c.Patterns {
			p := &c.Patterns[i]
			if p.Name == "" {
				return nil, fmt.Errorf("pattern %d has no name", i)
			}
			re, err := regexp.Compile(p.Regex)
			if err != nil {
				return nil, fmt.Errorf("pattern %s: %w", p.Name, err)
			}
			p.re = re
		}
	default:
		return nil, fmt.Errorf("mode must be %q or %q, got %q", ModeAuthz, ModeRedact, c.Mode)
	}
	return &c, nil
}

// Persona looks up a persona by name. An empty name never resolves.
func (c *Config) Persona(name string) (Persona, bool) {
	if name == "" {
		return Persona{}, false
	}
	p, ok := c.Personas[name]
	return p, ok
}

// Disabled reports whether a tool is switched off for every persona.
func (c *Config) Disabled(tool string) bool {
	for _, t := range c.DisabledTools {
		if t == tool {
			return true
		}
	}
	return false
}

// Allows reports whether the persona's tool list covers tool. "*" covers all.
func (p Persona) Allows(tool string) bool {
	for _, t := range p.Tools {
		if t == "*" || t == tool {
			return true
		}
	}
	return false
}
