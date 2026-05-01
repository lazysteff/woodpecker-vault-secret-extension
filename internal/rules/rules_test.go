package rules

import (
	"errors"
	"testing"

	"github.com/stephan/woodpecker-vault-secret-extension/internal/config"
	"github.com/stephan/woodpecker-vault-secret-extension/internal/woodpecker"
)

func TestRuleMatching(t *testing.T) {
	base := woodpecker.Request{
		Repo: woodpecker.Repo{Namespace: "Sendico", Name: "Sendico"},
		Pipeline: woodpecker.Pipeline{
			Event:  "push",
			Branch: "main",
			Ref:    "refs/heads/main",
		},
	}
	tests := []struct {
		name string
		rule config.RuleConfig
		req  woodpecker.Request
		want bool
	}{
		{
			name: "repo event branch match",
			rule: rule(config.RuleConfig{
				Repo:     "sendico/sendico",
				Events:   []string{"push"},
				Branches: []string{"main"},
			}),
			req:  base,
			want: true,
		},
		{
			name: "event mismatch",
			rule: rule(config.RuleConfig{
				Repo:   "sendico/sendico",
				Events: []string{"tag"},
			}),
			req:  base,
			want: false,
		},
		{
			name: "branch mismatch",
			rule: rule(config.RuleConfig{
				Repo:     "sendico/sendico",
				Events:   []string{"push"},
				Branches: []string{"release"},
			}),
			req:  base,
			want: false,
		},
		{
			name: "ref glob match",
			rule: rule(config.RuleConfig{
				Repo: "sendico/sendico",
				Refs: []string{"refs/heads/ma*"},
			}),
			req:  base,
			want: true,
		},
		{
			name: "tag shorthand matches ref",
			rule: rule(config.RuleConfig{
				Repo:   "sendico/sendico",
				Events: []string{"tag"},
				Tags:   []string{"v*"},
			}),
			req: woodpecker.Request{
				Repo:     base.Repo,
				Pipeline: woodpecker.Pipeline{Event: "tag", Branch: "main", Ref: "refs/tags/v1.2.3"},
			},
			want: true,
		},
		{
			name: "tag rule does not select by branch",
			rule: rule(config.RuleConfig{
				Repo:     "sendico/sendico",
				Events:   []string{"tag"},
				Branches: []string{"main"},
				Tags:     []string{"v*"},
			}),
			req: woodpecker.Request{
				Repo:     base.Repo,
				Pipeline: woodpecker.Pipeline{Event: "tag", Branch: "not-main", Ref: "refs/tags/v2.0.0"},
			},
			want: true,
		},
		{
			name: "pull request denied by default",
			rule: rule(config.RuleConfig{
				Repo:   "sendico/sendico",
				Events: []string{"pull_request"},
			}),
			req: woodpecker.Request{
				Repo:     base.Repo,
				Pipeline: woodpecker.Pipeline{Event: "pull_request", Branch: "feature", Ref: "refs/pull/1/head"},
			},
			want: false,
		},
		{
			name: "pull request explicitly allowed",
			rule: rule(config.RuleConfig{
				Repo:              "sendico/sendico",
				Events:            []string{"pull_request"},
				AllowPullRequests: true,
				AllowForks:        true,
			}),
			req: woodpecker.Request{
				Repo:     base.Repo,
				Pipeline: woodpecker.Pipeline{Event: "pull_request", Branch: "feature", Ref: "refs/pull/1/head"},
			},
			want: true,
		},
		{
			name: "fork denied",
			rule: rule(config.RuleConfig{
				Repo:              "sendico/sendico",
				Events:            []string{"pull_request"},
				AllowPullRequests: true,
			}),
			req:  mustDecode(t, `{"repo":{"namespace":"sendico","name":"sendico","fork":true},"pipeline":{"event":"pull_request","branch":"feature","ref":"refs/pull/1/head"}}`),
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewEngine([]config.RuleConfig{tt.rule}).Match(tt.req)
			if (len(got) == 1) != tt.want {
				t.Fatalf("matched=%v, want %v", len(got) == 1, tt.want)
			}
		})
	}
}

func TestDuplicateSecretNameAndCasing(t *testing.T) {
	matches := []Match{
		{Rule: rule(config.RuleConfig{Secrets: []config.SecretConfig{{Name: "VAULT_ADDR", Path: "a", Field: "x"}}})},
		{Rule: rule(config.RuleConfig{Secrets: []config.SecretConfig{{Name: "VAULT_ADDR", Path: "b", Field: "y"}}})},
	}
	_, err := CollectSecretRefs(matches)
	if !errors.Is(err, ErrDuplicateSecretName) {
		t.Fatalf("expected duplicate secret error, got %v", err)
	}
	matches[1].Rule.AllowOverride = true
	refs, err := CollectSecretRefs(matches)
	if err != nil {
		t.Fatalf("CollectSecretRefs: %v", err)
	}
	if len(refs) != 1 || refs[0].Name != "VAULT_ADDR" {
		t.Fatalf("secret name casing not preserved: %#v", refs)
	}
}

func rule(in config.RuleConfig) config.RuleConfig {
	if in.ID == "" {
		in.ID = "r1"
	}
	if in.Repo == "" {
		in.Repo = "sendico/sendico"
	}
	if len(in.Secrets) == 0 {
		in.Secrets = []config.SecretConfig{{Name: "TOKEN", Path: "p", Field: "f"}}
	}
	return in
}

func mustDecode(t *testing.T, body string) woodpecker.Request {
	t.Helper()
	req, err := woodpecker.Decode([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return *req
}
