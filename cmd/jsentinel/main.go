package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Hamt3er/jsentinel/internal/config"
	"github.com/Hamt3er/jsentinel/internal/report"
	"github.com/Hamt3er/jsentinel/internal/scanner"
)

func main() {
	var (
		filePath  string
		targetURL string
		siteURL   string
		jsonOut   string
		mdOut     string
		timeout   int
		maxPages  int
		maxJS     int
		concur    int
		ua        string
		sameHost  bool
		verbose   bool
	)

	flag.StringVar(&filePath, "file", "", "Path to local JavaScript file")
	flag.StringVar(&targetURL, "url", "", "Direct JavaScript URL")
	flag.StringVar(&siteURL, "site", "", "Website URL to crawl and collect JavaScript from")
	flag.StringVar(&jsonOut, "json-out", "", "Write JSON report to file")
	flag.StringVar(&mdOut, "md-out", "", "Write Markdown report to file")
	flag.IntVar(&timeout, "timeout", 15, "HTTP timeout in seconds")
	flag.IntVar(&maxPages, "max-pages", 15, "Maximum number of site pages to visit")
	flag.IntVar(&maxJS, "max-js", 50, "Maximum number of JS files to analyze")
	flag.IntVar(&concur, "concurrency", 6, "Maximum concurrent fetches")
	flag.StringVar(&ua, "ua", "JSentinel/1.0 (+Passive JavaScript Analysis)", "User-Agent")
	flag.BoolVar(&sameHost, "same-host", false, "Restrict crawling and JS collection to same host only")
	flag.BoolVar(&verbose, "v", false, "Verbose logs")
	flag.Parse()

	modeCount := 0
	for _, v := range []string{filePath, targetURL, siteURL} {
		if strings.TrimSpace(v) != "" {
			modeCount++
		}
	}
	if modeCount != 1 {
		fmt.Fprintln(os.Stderr, "You must use exactly one mode: -file OR -url OR -site")
		flag.Usage()
		os.Exit(1)
	}

	cfg := config.Config{
		FilePath:    strings.TrimSpace(filePath),
		TargetURL:   strings.TrimSpace(targetURL),
		SiteURL:     strings.TrimSpace(siteURL),
		JSONOut:     strings.TrimSpace(jsonOut),
		MDOut:       strings.TrimSpace(mdOut),
		TimeoutSec:  timeout,
		MaxPages:    maxPages,
		MaxJS:       maxJS,
		Concurrency: concur,
		UserAgent:   ua,
		SameHost:    sameHost,
		Verbose:     verbose,
	}

	rep, err := scanner.Run(cfg)
	if err != nil {
		log.Fatalf("scan failed: %v", err)
	}

	if cfg.JSONOut != "" {
		if err := report.WriteJSON(cfg.JSONOut, rep); err != nil {
			log.Fatalf("write json failed: %v", err)
		}
	}

	if cfg.MDOut != "" {
		if err := report.WriteMarkdown(cfg.MDOut, rep); err != nil {
			log.Fatalf("write markdown failed: %v", err)
		}
	}

	printConsole(rep)

	if cfg.JSONOut == "" {
		pretty, err := json.MarshalIndent(rep, "", "  ")
		if err == nil && cfg.Verbose {
			fmt.Println()
			fmt.Println(string(pretty))
		}
	}
}

func printConsole(rep report.Report) {
	fmt.Println("========== JSentinel Report ==========")
	fmt.Printf("Target: %s\n", rep.Target)
	fmt.Printf("Mode: %s\n", rep.Mode)
	fmt.Printf("Scanned At: %s\n", rep.ScannedAt)
	fmt.Printf("JS Files Analyzed: %d\n", len(rep.JavaScriptFiles))
	fmt.Println()

	fmt.Printf("Endpoints: %d\n", len(rep.Findings.Endpoints))
	fmt.Printf("Domains: %d\n", len(rep.Findings.Domains))
	fmt.Printf("API Paths: %d\n", len(rep.Findings.APIPaths))
	fmt.Printf("Suspected Secrets: %d\n", len(rep.Findings.SuspectedSecrets))
	fmt.Printf("Dangerous Sinks: %d\n", len(rep.Findings.DangerousSinks))
	fmt.Printf("Source Maps: %d\n", len(rep.Findings.SourceMaps))
	fmt.Printf("Storage Keys: %d\n", len(rep.Findings.StorageKeys))
	fmt.Println()

	if len(rep.Findings.SuspectedSecrets) > 0 {
		fmt.Println("---- Suspected Secrets ----")
		limit := min(10, len(rep.Findings.SuspectedSecrets))
		for i := 0; i < limit; i++ {
			s := rep.Findings.SuspectedSecrets[i]
			fmt.Printf("[%d] kind=%s confidence=%s source=%s preview=%s\n", i+1, s.Kind, s.Confidence, s.Source, s.ValuePreview)
		}
		fmt.Println()
	}

	if len(rep.Findings.SourceMaps) > 0 {
		fmt.Println("---- Source Maps ----")
		for _, sm := range rep.Findings.SourceMaps {
			fmt.Printf("- source=%s map=%s\n", sm.SourceFile, sm.MapURL)
		}
		fmt.Println()
	}

	if len(rep.Findings.DangerousSinks) > 0 {
		fmt.Println("---- Dangerous Sinks ----")
		limit := min(10, len(rep.Findings.DangerousSinks))
		for i := 0; i < limit; i++ {
			d := rep.Findings.DangerousSinks[i]
			fmt.Printf("[%d] sink=%s source=%s snippet=%s\n", i+1, d.Name, d.Source, d.Snippet)
		}
		fmt.Println()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
