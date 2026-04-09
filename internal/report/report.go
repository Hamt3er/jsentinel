package report

import (
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Report struct {
	Target          string      `json:"target"`
	Mode            string      `json:"mode"`
	ScannedAt       string      `json:"scanned_at"`
	JavaScriptFiles []JSFile    `json:"javascript_files"`
	Findings        Findings    `json:"findings"`
	Summary         Summary     `json:"summary"`
}

type JSFile struct {
	URL        string   `json:"url,omitempty"`
	Path       string   `json:"path,omitempty"`
	SizeBytes  int      `json:"size_bytes"`
	SourceMaps []string `json:"source_maps,omitempty"`
	MapSources []string `json:"map_sources,omitempty"`
}

type Finding struct {
	Value  string `json:"value"`
	Source string `json:"source"`
}

type SuspectedSecret struct {
	Kind         string `json:"kind"`
	ValuePreview string `json:"value_preview"`
	Confidence   string `json:"confidence"`
	Source       string `json:"source"`
}

type DangerousSink struct {
	Name    string `json:"name"`
	Snippet string `json:"snippet"`
	Source  string `json:"source"`
}

type SourceMapFinding struct {
	SourceFile string   `json:"source_file"`
	MapURL     string   `json:"map_url"`
	MapSources []string `json:"map_sources,omitempty"`
}

type Findings struct {
	Endpoints        []Finding          `json:"endpoints"`
	Domains          []Finding          `json:"domains"`
	APIPaths         []Finding          `json:"api_paths"`
	SuspectedSecrets []SuspectedSecret  `json:"suspected_secrets"`
	DangerousSinks   []DangerousSink    `json:"dangerous_sinks"`
	SourceMaps       []SourceMapFinding `json:"source_maps"`
	StorageKeys      []Finding          `json:"storage_keys"`
	InterestingLines []Finding          `json:"interesting_lines"`
}

type Summary struct {
	JSFiles          int `json:"js_files"`
	Endpoints        int `json:"endpoints"`
	Domains          int `json:"domains"`
	APIPaths         int `json:"api_paths"`
	SuspectedSecrets int `json:"suspected_secrets"`
	DangerousSinks   int `json:"dangerous_sinks"`
	SourceMaps       int `json:"source_maps"`
	StorageKeys      int `json:"storage_keys"`
}

func New(target, mode string) Report {
	return Report{
		Target:    target,
		Mode:      mode,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func Finalize(rep *Report) {
	sort.Slice(rep.JavaScriptFiles, func(i, j int) bool {
		return (rep.JavaScriptFiles[i].URL + rep.JavaScriptFiles[i].Path) < (rep.JavaScriptFiles[j].URL + rep.JavaScriptFiles[j].Path)
	})

	rep.Summary = Summary{
		JSFiles:          len(rep.JavaScriptFiles),
		Endpoints:        len(rep.Findings.Endpoints),
		Domains:          len(rep.Findings.Domains),
		APIPaths:         len(rep.Findings.APIPaths),
		SuspectedSecrets: len(rep.Findings.SuspectedSecrets),
		DangerousSinks:   len(rep.Findings.DangerousSinks),
		SourceMaps:       len(rep.Findings.SourceMaps),
		StorageKeys:      len(rep.Findings.StorageKeys),
	}
}

func WriteJSON(path string, rep Report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func WriteMarkdown(path string, rep Report) error {
	var b strings.Builder
	b.WriteString("# JSentinel Report\n\n")
	b.WriteString("## Overview\n\n")
	b.WriteString("- Target: " + rep.Target + "\n")
	b.WriteString("- Mode: " + rep.Mode + "\n")
	b.WriteString("- Scanned At: " + rep.ScannedAt + "\n")
	b.WriteString("- JS Files Analyzed: " + strconv.Itoa(len(rep.JavaScriptFiles)) + "\n\n")

	b.WriteString("## Summary\n\n")
	b.WriteString("- Endpoints: " + strconv.Itoa(len(rep.Findings.Endpoints)) + "\n")
	b.WriteString("- Domains: " + strconv.Itoa(len(rep.Findings.Domains)) + "\n")
	b.WriteString("- API Paths: " + strconv.Itoa(len(rep.Findings.APIPaths)) + "\n")
	b.WriteString("- Suspected Secrets: " + strconv.Itoa(len(rep.Findings.SuspectedSecrets)) + "\n")
	b.WriteString("- Dangerous Sinks: " + strconv.Itoa(len(rep.Findings.DangerousSinks)) + "\n")
	b.WriteString("- Source Maps: " + strconv.Itoa(len(rep.Findings.SourceMaps)) + "\n")
	b.WriteString("- Storage Keys: " + strconv.Itoa(len(rep.Findings.StorageKeys)) + "\n\n")

	if len(rep.JavaScriptFiles) > 0 {
		b.WriteString("## JavaScript Files\n\n")
		for _, jf := range rep.JavaScriptFiles {
			item := jf.URL
			if item == "" {
				item = jf.Path
			}
			b.WriteString("- " + item + "\n")
		}
		b.WriteString("\n")
	}

	writeFindingSection := func(title string, items []Finding) {
		if len(items) == 0 {
			return
		}
		b.WriteString("## " + title + "\n\n")
		for _, item := range items {
			b.WriteString("- `" + safe(item.Value) + "`")
			if item.Source != "" {
				b.WriteString(" — source: `" + safe(item.Source) + "`")
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	writeFindingSection("Endpoints", rep.Findings.Endpoints)
	writeFindingSection("Domains", rep.Findings.Domains)
	writeFindingSection("API Paths", rep.Findings.APIPaths)
	writeFindingSection("Storage Keys", rep.Findings.StorageKeys)
	writeFindingSection("Interesting Lines", rep.Findings.InterestingLines)

	if len(rep.Findings.SuspectedSecrets) > 0 {
		b.WriteString("## Suspected Secrets\n\n")
		for _, s := range rep.Findings.SuspectedSecrets {
			b.WriteString("- kind: `" + safe(s.Kind) + "`, confidence: `" + safe(s.Confidence) + "`, preview: `" + safe(s.ValuePreview) + "`, source: `" + safe(s.Source) + "`\n")
		}
		b.WriteString("\n")
	}

	if len(rep.Findings.DangerousSinks) > 0 {
		b.WriteString("## Dangerous Sinks\n\n")
		for _, d := range rep.Findings.DangerousSinks {
			b.WriteString("- sink: `" + safe(d.Name) + "`, source: `" + safe(d.Source) + "`\n")
			b.WriteString("  - snippet: `" + safe(d.Snippet) + "`\n")
		}
		b.WriteString("\n")
	}

	if len(rep.Findings.SourceMaps) > 0 {
		b.WriteString("## Source Maps\n\n")
		for _, sm := range rep.Findings.SourceMaps {
			b.WriteString("- source file: `" + safe(sm.SourceFile) + "`, map: `" + safe(sm.MapURL) + "`\n")
			for _, src := range sm.MapSources {
				b.WriteString("  - original source: `" + safe(src) + "`\n")
			}
		}
		b.WriteString("\n")
	}

	return os.WriteFile(path, []byte(b.String()), 0644)
}

func safe(s string) string {
	return strings.ReplaceAll(s, "`", "'")
}
