package rules

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/config"
	"github.com/lazysteff/woodpecker-vault-secret-extension/internal/woodpecker"
)

var ErrDuplicateSecretName = errors.New("duplicate secret name")

type Engine struct {
	Rules []config.RuleConfig
}

type Match struct {
	Rule config.RuleConfig
}

type SecretRef struct {
	RuleID string
	Name   string
	Path   string
	Field  string
	Events []string
	Images []string
}

func NewEngine(cfg []config.RuleConfig) Engine {
	return Engine{Rules: cfg}
}

func (e Engine) Match(req woodpecker.Request) []Match {
	out := make([]Match, 0)
	for _, rule := range e.Rules {
		if matchRule(rule, req) {
			out = append(out, Match{Rule: rule})
		}
	}
	return out
}

func CollectSecretRefs(matches []Match) ([]SecretRef, error) {
	refs := make([]SecretRef, 0)
	seen := map[string]int{}
	for _, match := range matches {
		for _, secret := range match.Rule.Secrets {
			ref := SecretRef{
				RuleID: match.Rule.ID,
				Name:   secret.Name,
				Path:   secret.Path,
				Field:  secret.Field,
				Events: clone(secret.Events),
				Images: clone(secret.Images),
			}
			if idx, ok := seen[secret.Name]; ok {
				if !match.Rule.AllowOverride {
					return nil, fmt.Errorf("%w: %s", ErrDuplicateSecretName, secret.Name)
				}
				refs[idx] = ref
				continue
			}
			seen[secret.Name] = len(refs)
			refs = append(refs, ref)
		}
	}
	return refs, nil
}

func matchRule(rule config.RuleConfig, req woodpecker.Request) bool {
	repo, ok := req.RepoIdentity()
	if !ok || repo != strings.ToLower(rule.Repo) {
		return false
	}
	if !req.TagMetadataConsistent() {
		return false
	}
	if len(rule.Events) > 0 && !containsExact(rule.Events, req.Pipeline.Event) {
		return false
	}
	if req.IsPullRequest() && !rule.AllowPullRequests {
		return false
	}
	if !rule.AllowForks {
		if forked, known := req.ForkStatus(); forked || (!known && req.IsPullRequest()) {
			return false
		}
	}
	if len(rule.Branches) > 0 && !req.IsTag() {
		if req.Pipeline.Branch == "" || !containsExact(rule.Branches, req.Pipeline.Branch) {
			return false
		}
	}
	refs := expandedRefs(rule)
	if len(refs) > 0 {
		if req.Pipeline.Ref == "" {
			return false
		}
		if !matchesAnyGlob(refs, req.Pipeline.Ref) {
			return false
		}
	}
	return true
}

func expandedRefs(rule config.RuleConfig) []string {
	refs := clone(rule.Refs)
	for _, tag := range rule.Tags {
		refs = append(refs, "refs/tags/"+tag)
	}
	return refs
}

func containsExact(values []string, got string) bool {
	for _, value := range values {
		if value == got {
			return true
		}
	}
	return false
}

func matchesAnyGlob(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if globMatch(pattern, value) {
			return true
		}
	}
	return false
}

func globMatch(pattern, value string) bool {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	ok, err := regexp.MatchString(b.String(), value)
	return err == nil && ok
}

func clone(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
