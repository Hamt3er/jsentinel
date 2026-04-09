package fetcher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Fetcher struct {
	client    *http.Client
	userAgent string
}

type Result struct {
	URL         string
	Body        []byte
	StatusCode  int
	ContentType string
}

func New(timeoutSec int, userAgent string) *Fetcher {
	return &Fetcher{
		client: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		userAgent: userAgent,
	}
}

func (f *Fetcher) Get(ctx context.Context, target string) (*Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.userAgent)
	req.Header.Set("Accept", "*/*")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 20*1024*1024))
	if err != nil {
		return nil, err
	}

	return &Result{
		URL:         target,
		Body:        body,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
	}, nil
}

func ResolveURL(baseURL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}

	bu, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return bu.ResolveReference(ru).String()
}

func SameHost(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil {
		return false
	}
	return strings.EqualFold(ua.Hostname(), ub.Hostname())
}
