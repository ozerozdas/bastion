package github

// User is the account a token belongs to (GET /user). Only the fields bastion
// shows on the Connections page are decoded.
type User struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	ID    int64  `json:"id"`
}

// Owner is the account that owns a repository.
type Owner struct {
	Login string `json:"login"`
}

// Repo is a repository as the API describes it. Only the fields bastion uses
// are decoded.
type Repo struct {
	FullName      string `json:"full_name"`
	Name          string `json:"name"`
	Owner         Owner  `json:"owner"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
}
