package version

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var (
	AppName = "JSentinel"
	Author  = "Hamt3er"

	// This value can be overridden at build time using:
	// -ldflags "-X 'github.com/Hamt3er/jsentinel/internal/version.Version=1.0.0'"
	Version = "dev"

	RepoOwner = "Hamt3er"
	RepoName  = "jsentinel"
)

type ReleaseInfo struct {
	CurrentVersion string
	LatestVersion  string
	IsLatest       bool
	Message        string
}

type githubRelease struct {
	TagName string `json:"tag_name"`
}

func CheckLatest(ctx context.Context) ReleaseInfo {
	info := ReleaseInfo{
		CurrentVersion: normalizeVersion(Version),
		LatestVersion:  "unknown",
		IsLatest:       false,
		Message:        "update status unknown",
	}

	if strings.TrimSpace(Version) == "" {
		info.CurrentVersion = "dev"
	}

	client := &http.Client{
		Timeout: 4 * time.Second,
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", RepoOwner, RepoName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		info.Message = "failed to create update request"
		return info
	}

	req.Header.Set("User-Agent", AppName+"/"+info.CurrentVersion)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		info.Message = "could not check latest version"
		return info
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		info.Message = "no published release found"
		return info
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		info.Message = "failed to parse latest version info"
		return info
	}

	latest := normalizeVersion(rel.TagName)
	if latest == "" {
		info.Message = "latest version not available"
		return info
	}

	info.LatestVersion = latest

	current := normalizeVersion(info.CurrentVersion)
	if current == "" || current == "dev" {
		info.IsLatest = false
		info.Message = "development build"
		return info
	}

	if compareVersions(current, latest) >= 0 {
		info.IsLatest = true
		info.Message = "latest version installed"
		return info
	}

	info.IsLatest = false
	info.Message = "update available"
	return info
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	return v
}

func compareVersions(a, b string) int {
	as := splitVersion(a)
	bs := splitVersion(b)

	maxLen := len(as)
	if len(bs) > maxLen {
		maxLen = len(bs)
	}

	for i := 0; i < maxLen; i++ {
		av := 0
		bv := 0

		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}

		if av > bv {
			return 1
		}
		if av < bv {
			return -1
		}
	}

	return 0
}

func splitVersion(v string) []int {
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))

	for _, p := range parts {
		n := 0
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				break
			}
			n = n*10 + int(ch-'0')
		}
		out = append(out, n)
	}

	return out
}
