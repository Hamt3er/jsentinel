package parser

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	reScriptSrc        = regexp.MustCompile(`(?is)<script[^>]+src=["']([^"']+)["']`)
	reHref             = regexp.MustCompile(`(?is)<a[^>]+href=["']([^"']+)["']`)
	reURLLike          = regexp.MustCompile(`https?://[a-zA-Z0-9\.\-\_\~:/?#\[\]@!\$&'\(\)\*\+,;=%]+`)
	reAPIPath          = regexp.MustCompile(`(?i)(/api/[a-zA-Z0-9_\-./?=&%]+|/v[0-9]+/[a-zA-Z0-9_\-./?=&%]+)`)
	reQuotedPath       = regexp.MustCompile(`["']((?:/|\.{1,2}/)[^"'\\\s]{2,})["']`)
	reMap              = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=([^\s]+)`)
	reJWT              = regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9._-]{8,}\.[a-zA-Z0-9._-]{8,}\b`)
	reGoogleAPI        = regexp.MustCompile(`AIza[0-9A-Za-z\-_]{20,}`)
	reAWSKey           = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reGitHubPat        = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{20,}\b`)
	reSlackTok         = regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)
	reGenericKV        = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|bearer|authorization|client[_-]?secret|private[_-]?key)["'\s:=]{1,12}([A-Za-z0-9_\-\/\+=\.]{8,})`)
	reStorage          = regexp.MustCompile(`(?i)(localStorage|sessionStorage)\.(getItem|setItem)\(["']([^"']+)["']\)`)
	reDangerous        = regexp.MustCompile(`(?i)(eval\s*\(|new Function\s*\(|innerHTML\s*=|outerHTML\s*=|document\.write\s*\(|postMessage\s*\(|XMLHttpRequest|fetch\s*\(|WebSocket\s*\()`)
	reWordishSecretName = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|auth|bearer|private[_-]?key|client[_-]?secret)`)
)

type JSParsed struct {
	Endpoints         []string
	Domains           []string
	APIPaths          []string
	SourceMaps        []string
	JWTs              []string
	GoogleAPIKeys     []string
	AWSKeys           []string
	GitHubTokens      []string
	SlackTokens       []string
	GenericSecrets    []SecretKV
	StorageKeys       []string
	DangerousSnippets []DangerousSnippet
	InterestingLines  []string
}

type SecretKV struct {
	Name  string
	Value string
}

type DangerousSnippet struct {
	Name    string
	Snippet string
}

func ExtractScriptSources(html string) []string {
	var out []string
	for _, m := range reScriptSrc.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 {
			out = append(out, strings.TrimSpace(m[1]))
		}
	}
	return uniq(out)
}

func ExtractLinks(html string) []string {
	var out []string
	for _, m := range reHref.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 {
			out = append(out, strings.TrimSpace(m[1]))
		}
	}
	return uniq(out)
}

func ParseJS(content string) JSParsed {
	var p JSParsed

	p.Endpoints = uniq(reURLLike.FindAllString(content, -1))
	p.APIPaths = uniq(reAPIPath.FindAllString(content, -1))

	for _, m := range reQuotedPath.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			p.APIPaths = append(p.APIPaths, strings.TrimSpace(m[1]))
		}
	}
	p.APIPaths = uniq(p.APIPaths)

	for _, ep := range p.Endpoints {
		if u, err := url.Parse(ep); err == nil && u.Host != "" {
			p.Domains = append(p.Domains, u.Host)
		}
	}
	p.Domains = uniq(p.Domains)

	for _, m := range reMap.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			p.SourceMaps = append(p.SourceMaps, strings.TrimSpace(m[1]))
		}
	}
	p.SourceMaps = uniq(p.SourceMaps)

	p.JWTs = uniq(reJWT.FindAllString(content, -1))
	p.GoogleAPIKeys = uniq(reGoogleAPI.FindAllString(content, -1))
	p.AWSKeys = uniq(reAWSKey.FindAllString(content, -1))
	p.GitHubTokens = uniq(reGitHubPat.FindAllString(content, -1))
	p.SlackTokens = uniq(reSlackTok.FindAllString(content, -1))

	for _, m := range reGenericKV.FindAllStringSubmatch(content, -1) {
		if len(m) > 2 {
			p.GenericSecrets = append(p.GenericSecrets, SecretKV{
				Name:  strings.TrimSpace(m[1]),
				Value: strings.TrimSpace(m[2]),
			})
		}
	}

	for _, m := range reStorage.FindAllStringSubmatch(content, -1) {
		if len(m) > 3 {
			p.StorageKeys = append(p.StorageKeys, strings.TrimSpace(m[3]))
		}
	}
	p.StorageKeys = uniq(p.StorageKeys)

	for _, m := range reDangerous.FindAllStringIndex(content, -1) {
		start := m[0] - 60
		end := m[1] + 120

		if start < 0 {
			start = 0
		}
		if end > len(content) {
			end = len(content)
		}

		snip := oneLine(content[start:end])
		name := oneLine(content[m[0]:m[1]])

		p.DangerousSnippets = append(p.DangerousSnippets, DangerousSnippet{
			Name:    name,
			Snippet: snip,
		})
	}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		l := strings.TrimSpace(line)
		if len(l) == 0 || len(l) > 400 {
			continue
		}
		if reWordishSecretName.MatchString(l) || strings.Contains(strings.ToLower(l), "sourcemap") {
			p.InterestingLines = append(p.InterestingLines, l)
		}
	}
	p.InterestingLines = uniq(p.InterestingLines)

	return p
}

func TryParseSourceMapSources(mapContent []byte) []string {
	type sourceMap struct {
		Sources []string `json:"sources"`
	}

	var sm sourceMap
	if err := json.Unmarshal(mapContent, &sm); err != nil {
		return nil
	}

	return uniq(sm.Sources)
}

func uniq(in []string) []string {
	seen := make(map[string]struct{})
	var out []string

	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}

	sort.Strings(out)
	return out
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.Join(strings.Fields(s), " ")

	if len(s) > 220 {
		return s[:220] + "..."
	}

	return s
}
