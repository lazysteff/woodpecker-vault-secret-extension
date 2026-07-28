package woodpecker

import (
	"encoding/json"
	"errors"
	"strings"
)

type Request struct {
	Repo     Repo           `json:"repo"`
	Pipeline Pipeline       `json:"pipeline"`
	Netrc    map[string]any `json:"netrc,omitempty"`
	Raw      map[string]any `json:"-"`
	rawRepo  map[string]any `json:"-"`
	rawPipe  map[string]any `json:"-"`
}

type Repo struct {
	FullName  string `json:"full_name"`
	Slug      string `json:"slug"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type Pipeline struct {
	Event   string `json:"event"`
	Branch  string `json:"branch"`
	Ref     string `json:"ref"`
	Refspec string `json:"refspec"`
}

type Secret struct {
	Name   string   `json:"name"`
	Value  string   `json:"value"`
	Events []string `json:"events,omitempty"`
	Images []string `json:"images,omitempty"`
}

type Response struct {
	Secrets []Secret `json:"secrets"`
}

func Decode(b []byte) (*Request, error) {
	var req Request
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	req.Raw = raw
	repoRaw, ok := raw["repo"].(map[string]any)
	if !ok {
		return nil, errors.New("repo must be an object")
	}
	pipeRaw, ok := raw["pipeline"].(map[string]any)
	if !ok {
		return nil, errors.New("pipeline must be an object")
	}
	req.rawRepo = repoRaw
	req.rawPipe = pipeRaw
	return &req, nil
}

func (r Request) RepoIdentity() (string, bool) {
	if r.Repo.FullName != "" {
		return strings.ToLower(r.Repo.FullName), true
	}
	if r.Repo.Slug != "" {
		return strings.ToLower(r.Repo.Slug), true
	}
	if r.Repo.Namespace != "" && r.Repo.Name != "" {
		return strings.ToLower(r.Repo.Namespace + "/" + r.Repo.Name), true
	}
	return "", false
}

func (r Request) RepoForLog() string {
	if id, ok := r.RepoIdentity(); ok {
		return id
	}
	return ""
}

func (r Request) IsPullRequest() bool {
	event := strings.ToLower(r.Pipeline.Event)
	return event == "pull_request" || strings.HasPrefix(event, "pull_request_") || event == "pull-request" || event == "pr"
}

func (r Request) IsTag() bool {
	return strings.EqualFold(r.Pipeline.Event, "tag")
}

func (r Request) TagMetadataConsistent() bool {
	return r.IsTag() == strings.HasPrefix(r.Pipeline.Ref, "refs/tags/")
}

func (r Request) ForkStatus() (forked bool, known bool) {
	for _, raw := range []map[string]any{r.rawPipe, r.rawRepo, r.Raw} {
		if v, ok := lookupBool(raw, "fork", "forked", "is_fork", "from_fork"); ok {
			return v, true
		}
	}
	return false, false
}

func lookupBool(raw map[string]any, names ...string) (bool, bool) {
	if raw == nil {
		return false, false
	}
	for _, name := range names {
		if v, ok := raw[name]; ok {
			b, ok := v.(bool)
			if ok {
				return b, true
			}
		}
	}
	return false, false
}
