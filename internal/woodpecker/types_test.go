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
		name   string
		event  string
		branch string
		ref    string
		want   bool
	}{
		{name: "tag event and ref", event: "tag", ref: "refs/tags/v1.2.3", want: true},
		{name: "push event and branch ref", event: "push", branch: "main", ref: "refs/heads/main", want: true},
		{name: "push branch and ref disagree", event: "push", branch: "main", ref: "refs/heads/feature", want: false},
		{name: "push missing branch", event: "push", ref: "refs/heads/main", want: false},
		{name: "push missing ref", event: "push", branch: "main", want: false},
		{name: "tag event with branch ref", event: "tag", ref: "refs/heads/main", want: false},
		{name: "push event with tag ref", event: "push", branch: "main", ref: "refs/tags/v1.2.3", want: false},
		{name: "pull request with tag ref", event: "pull_request", ref: "refs/tags/v1.2.3", want: false},
		{name: "tag event without ref", event: "tag", want: false},
		{name: "release event with tag ref", event: "release", ref: "refs/tags/v1.2.3", want: true},
		{name: "manual event with tag ref", event: "manual", ref: "refs/tags/v1.2.3", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := Request{Pipeline: Pipeline{Event: tt.event, Branch: tt.branch, Ref: tt.ref}}
			if got := req.EventRefConsistent(); got != tt.want {
				t.Fatalf("EventRefConsistent()=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestForkStatusAggregatesAllSignals(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantForked bool
		wantKnown  bool
	}{
		{
			name:       "single false signal is known non fork",
			body:       `{"repo":{},"pipeline":{"from_fork":false}}`,
			wantKnown:  true,
			wantForked: false,
		},
		{
			name:       "later true signal overrides earlier false",
			body:       `{"repo":{"fork":true},"pipeline":{"from_fork":false}}`,
			wantKnown:  true,
			wantForked: true,
		},
		{
			name:       "invalid and false signals remain unknown",
			body:       `{"repo":{"fork":false},"pipeline":{"from_fork":"false"}}`,
			wantKnown:  false,
			wantForked: false,
		},
		{
			name:       "missing signals remain unknown",
			body:       `{"repo":{},"pipeline":{}}`,
			wantKnown:  false,
			wantForked: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := Decode([]byte(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			forked, known := req.ForkStatus()
			if forked != tt.wantForked || known != tt.wantKnown {
				t.Fatalf("ForkStatus()=(%v, %v), want (%v, %v)", forked, known, tt.wantForked, tt.wantKnown)
			}
		})
	}
}
