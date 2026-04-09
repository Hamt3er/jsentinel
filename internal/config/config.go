package config

type Config struct {
	FilePath    string
	TargetURL   string
	SiteURL     string
	JSONOut     string
	MDOut       string
	TimeoutSec  int
	MaxPages    int
	MaxJS       int
	Concurrency int
	UserAgent   string
	SameHost    bool
	Verbose     bool
}
