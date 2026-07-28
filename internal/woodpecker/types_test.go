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
