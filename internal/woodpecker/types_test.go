package woodpecker

import "testing"

func TestIsPullRequest(t *testing.T) {
	tests := []struct {
		event string
		want  bool
	}{
		{event: "pull_request", want: true},
		{event: "pull_request_closed", want: true},
		{event: "pull_request_metadata", want: true},
		{event: "pull_request_future_variant", want: true},
		{event: "PULL_REQUEST_FUTURE_VARIANT", want: true},
		{event: "pull-request", want: true},
		{event: "pr", want: true},
		{event: "push", want: false},
		{event: "tag", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.event, func(t *testing.T) {
			req := Request{Pipeline: Pipeline{Event: tt.event}}
			if got := req.IsPullRequest(); got != tt.want {
				t.Fatalf("IsPullRequest()=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestEventRefConsistent(t *testing.T) {
	tests := []struct {
		name  string
		event string
		ref   string
		want  bool
	}{
		{name: "tag event and ref", event: "tag", ref: "refs/tags/v1.2.3", want: true},
		{name: "push event and branch ref", event: "push", ref: "refs/heads/main", want: true},
		{name: "tag event with branch ref", event: "tag", ref: "refs/heads/main", want: false},
		{name: "push event with tag ref", event: "push", ref: "refs/tags/v1.2.3", want: false},
		{name: "pull request with tag ref", event: "pull_request", ref: "refs/tags/v1.2.3", want: false},
		{name: "tag event without ref", event: "tag", want: false},
		{name: "release event with tag ref", event: "release", ref: "refs/tags/v1.2.3", want: true},
		{name: "manual event with tag ref", event: "manual", ref: "refs/tags/v1.2.3", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := Request{Pipeline: Pipeline{Event: tt.event, Ref: tt.ref}}
			if got := req.EventRefConsistent(); got != tt.want {
				t.Fatalf("EventRefConsistent()=%v want=%v", got, tt.want)
			}
		})
	}
}
