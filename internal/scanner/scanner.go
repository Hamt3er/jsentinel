package scanner

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/Hamt3er/jsentinel/internal/config"
	"github.com/Hamt3er/jsentinel/internal/fetcher"
	"github.com/Hamt3er/jsentinel/internal/parser"
	"github.com/Hamt3er/jsentinel/internal/report"
)

type jsJob struct {
	URL  string
	Path string
	Body []byte
}

func Run(cfg config.Config) (report.Report, error) {
	switch {
	case cfg.FilePath != "":
		return runFile(cfg)
	case cfg.TargetURL != "":
		return runURL(cfg)
	case cfg.SiteURL != "":
		return runSite(cfg)
	default:
		return report.Report{}, fmt.Errorf("no mode selected")
	}
}

func runFile(cfg config.Config) (report.Report, error) {
	data, err := os.ReadFile(cfg.FilePath)
	if err != nil {
		return report.Report{}, err
	}
	rep := report.New(cfg.FilePath, "file")
	analyzeJS(&rep, jsJob{Path: cfg.FilePath, Body: data}, nil)
	report.Finalize(&rep)
	return rep, nil
}

func runURL(cfg config.Config) (report.Report, error) {
	f := fetcher.New(cfg.TimeoutSec, cfg.UserAgent)
	ctx := context.Background()

	res, err := f.Get(ctx, cfg.TargetURL)
	if err != nil {
		return report.Report{}, err
	}
	rep := report.New(cfg.TargetURL, "url")
	analyzeJS(&rep, jsJob{URL: cfg.TargetURL, Body: res.Body}, f)
	report.Finalize(&rep)
	return rep, nil
}

func runSite(cfg config.Config) (report.Report, error) {
	f := fetcher.New(cfg.TimeoutSec, cfg.UserAgent)
	ctx := context.Background()

	rep := report.New(cfg.SiteURL, "site")

	visitedPages := map[string]struct{}{}
	visitedJS := map[string]struct{}{}
	pageQueue := []string{cfg.SiteURL}
	var jsURLs []string

	for len(pageQueue) > 0 && len(visitedPages) < cfg.MaxPages {
		page := pageQueue[0]
		pageQueue = pageQueue[1:]
		if _, ok := visitedPages[page]; ok {
			continue
		}
		visitedPages[page] = struct{}{}

		res, err := f.Get(ctx, page)
		if err != nil {
			continue
		}
		body := string(res.Body)

		for _, src := range parser.ExtractScriptSources(body) {
			full := fetcher.ResolveURL(page, src)
			if full == "" {
				continue
			}
			if cfg.SameHost && !fetcher.SameHost(cfg.SiteURL, full) {
				continue
			}
			if _, ok := visitedJS[full]; ok {
				continue
			}
			visitedJS[full] = struct{}{}
			jsURLs = append(jsURLs, full)
		}

		for _, href := range parser.ExtractLinks(body) {
			full := fetcher.ResolveURL(page, href)
			if full == "" {
				continue
			}
			if cfg.SameHost && !fetcher.SameHost(cfg.SiteURL, full) {
				continue
			}
			if !strings.HasPrefix(full, "http://") && !strings.HasPrefix(full, "https://") {
				continue
			}
			if _, ok := visitedPages[full]; ok {
				continue
			}
			pageQueue = append(pageQueue, full)
		}
	}

	for _, extra := range []string{"/robots.txt", "/sitemap.xml"} {
		u := strings.TrimRight(cfg.SiteURL, "/") + extra
		res, err := f.Get(ctx, u)
		if err != nil {
			continue
		}
		body := string(res.Body)
		for _, found := range parser.ExtractLinks(body) {
			full := fetcher.ResolveURL(u, found)
			if full == "" {
				continue
			}
			if cfg.SameHost && !fetcher.SameHost(cfg.SiteURL, full) {
				continue
			}
			pageQueue = append(pageQueue, full)
		}
		for _, found := range parser.ParseJS(body).Endpoints {
			if strings.HasSuffix(strings.ToLower(found), ".js") {
				if cfg.SameHost && !fetcher.SameHost(cfg.SiteURL, found) {
					continue
				}
				jsURLs = append(jsURLs, found)
			}
		}
	}

	jsURLs = dedupe(jsURLs)
	if len(jsURLs) > cfg.MaxJS {
		jsURLs = jsURLs[:cfg.MaxJS]
	}

	jobs := make(chan string)
	results := make(chan jsJob)
	wg := sync.WaitGroup{}

	workers := cfg.Concurrency
	if workers < 1 {
		workers = 1
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				res, err := f.Get(ctx, u)
				if err != nil {
					continue
				}
				results <- jsJob{URL: u, Body: res.Body}
			}
		}()
	}

	go func() {
		for _, u := range jsURLs {
			jobs <- u
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	for job := range results {
		analyzeJS(&rep, job, f)
	}

	report.Finalize(&rep)
	return rep, nil
}

func analyzeJS(rep *report.Report, job jsJob, f *fetcher.Fetcher) {
	if len(job.Body) == 0 {
		return
	}

	jf := report.JSFile{
		URL:       job.URL,
		Path:      job.Path,
		SizeBytes: len(job.Body),
	}

	content := string(job.Body)
	parsed := parser.ParseJS(content)
	sourceRef := job.URL
	if sourceRef == "" {
		sourceRef = job.Path
	}

	appendFindings := func(values []string, dest *[]report.Finding) {
		for _, v := range values {
			*dest = append(*dest, report.Finding{Value: v, Source: sourceRef})
		}
	}

	appendFindings(parsed.Endpoints, &rep.Findings.Endpoints)
	appendFindings(parsed.Domains, &rep.Findings.Domains)
	appendFindings(parsed.APIPaths, &rep.Findings.APIPaths)
	appendFindings(parsed.StorageKeys, &rep.Findings.StorageKeys)
	appendFindings(parsed.InterestingLines, &rep.Findings.InterestingLines)

	for _, v := range parsed.JWTs {
		rep.Findings.SuspectedSecrets = append(rep.Findings.SuspectedSecrets, report.SuspectedSecret{
			Kind:         "JWT-like",
			ValuePreview: preview(v),
			Confidence:   "medium",
			Source:       sourceRef,
		})
	}
	for _, v := range parsed.GoogleAPIKeys {
		rep.Findings.SuspectedSecrets = append(rep.Findings.SuspectedSecrets, report.SuspectedSecret{
			Kind:         "Google API Key-like",
			ValuePreview: preview(v),
			Confidence:   "high",
			Source:       sourceRef,
		})
	}
	for _, v := range parsed.AWSKeys {
		rep.Findings.SuspectedSecrets = append(rep.Findings.SuspectedSecrets, report.SuspectedSecret{
			Kind:         "AWS Access Key-like",
			ValuePreview: preview(v),
			Confidence:   "high",
			Source:       sourceRef,
		})
	}
	for _, v := range parsed.GitHubTokens {
		rep.Findings.SuspectedSecrets = append(rep.Findings.SuspectedSecrets, report.SuspectedSecret{
			Kind:         "GitHub Token-like",
			ValuePreview: preview(v),
			Confidence:   "high",
			Source:       sourceRef,
		})
	}
	for _, v := range parsed.SlackTokens {
		rep.Findings.SuspectedSecrets = append(rep.Findings.SuspectedSecrets, report.SuspectedSecret{
			Kind:         "Slack Token-like",
			ValuePreview: preview(v),
			Confidence:   "high",
			Source:       sourceRef,
		})
	}
	for _, kv := range parsed.GenericSecrets {
		rep.Findings.SuspectedSecrets = append(rep.Findings.SuspectedSecrets, report.SuspectedSecret{
			Kind:         "Generic secret key/value: " + kv.Name,
			ValuePreview: preview(kv.Value),
			Confidence:   "low",
			Source:       sourceRef,
		})
	}

	for _, d := range parsed.DangerousSnippets {
		rep.Findings.DangerousSinks = append(rep.Findings.DangerousSinks, report.DangerousSink{
			Name:    d.Name,
			Snippet: d.Snippet,
			Source:  sourceRef,
		})
	}

	if len(parsed.SourceMaps) > 0 {
		jf.SourceMaps = append(jf.SourceMaps, parsed.SourceMaps...)
	}

	if f != nil && job.URL != "" {
		for _, sm := range parsed.SourceMaps {
			mapURL := fetcher.ResolveURL(job.URL, sm)
			mapSources := []string(nil)
			if mapURL != "" {
				res, err := f.Get(context.Background(), mapURL)
				if err == nil {
					mapSources = parser.TryParseSourceMapSources(res.Body)
					jf.MapSources = append(jf.MapSources, mapSources...)
				}
				rep.Findings.SourceMaps = append(rep.Findings.SourceMaps, report.SourceMapFinding{
					SourceFile: sourceRef,
					MapURL:     mapURL,
					MapSources: mapSources,
				})
			}
		}
	}

	rep.JavaScriptFiles = append(rep.JavaScriptFiles, jf)
	dedupeReport(rep)
}

func dedupe(values []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func dedupeReport(rep *report.Report) {
	rep.Findings.Endpoints = dedupeFinding(rep.Findings.Endpoints)
	rep.Findings.Domains = dedupeFinding(rep.Findings.Domains)
	rep.Findings.APIPaths = dedupeFinding(rep.Findings.APIPaths)
	rep.Findings.StorageKeys = dedupeFinding(rep.Findings.StorageKeys)
	rep.Findings.InterestingLines = dedupeFinding(rep.Findings.InterestingLines)
	rep.Findings.SuspectedSecrets = dedupeSecrets(rep.Findings.SuspectedSecrets)
	rep.Findings.DangerousSinks = dedupeSinks(rep.Findings.DangerousSinks)
	rep.Findings.SourceMaps = dedupeSourceMaps(rep.Findings.SourceMaps)
}

func dedupeFinding(in []report.Finding) []report.Finding {
	seen := map[string]struct{}{}
	var out []report.Finding
	for _, item := range in {
		key := item.Value + "|" + item.Source
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

func dedupeSecrets(in []report.SuspectedSecret) []report.SuspectedSecret {
	seen := map[string]struct{}{}
	var out []report.SuspectedSecret
	for _, item := range in {
		key := item.Kind + "|" + item.ValuePreview + "|" + item.Source
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func dedupeSinks(in []report.DangerousSink) []report.DangerousSink {
	seen := map[string]struct{}{}
	var out []report.DangerousSink
	for _, item := range in {
		key := item.Name + "|" + item.Snippet + "|" + item.Source
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func dedupeSourceMaps(in []report.SourceMapFinding) []report.SourceMapFinding {
	seen := map[string]struct{}{}
	var out []report.SourceMapFinding
	for _, item := range in {
		key := item.SourceFile + "|" + item.MapURL
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func preview(v string) string {
	if len(v) <= 18 {
		return v
	}
	return v[:8] + "..." + v[len(v)-6:]
}
