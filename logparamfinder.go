package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	urlme "net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// Config holds spider configuration
type Config struct {
	URL           string
	MaxDepth      int
	MaxConcurrent int
	Timeout       int
	UserAgent     string
	OutputFile    string
	UseHeaders    bool
	Verbose       bool
}

// Spider represents the web crawler
type Spider struct {
	config         Config
	client         *http.Client
	visited        map[string]bool
	visitedMutex   sync.RWMutex
	results        []Result
	resultsMutex   sync.Mutex
	commonParams   []string
	sensitivePaths []string
	wg             sync.WaitGroup
	queue          chan Task
}

// Task represents a crawling task
type Task struct {
	URL   string
	Depth int
}

// Result represents a found parameter or endpoint
type Result struct {
	URL        string
	Type       string
	Parameter  string
	Value      string
	Confidence string
	Source     string
}

// Common logging/backend related parameters
var commonLogParams = []string{
	// Logging parameters
	"log", "logger", "logging", "loglevel", "log_level", "logLevel",
	"debug", "verbose", "trace", "diagnostics",
	"console", "stdout", "stderr",
	
	// Monitoring/Admin parameters
	"admin", "administrator", "sysadmin", "root",
	"monitor", "monitoring", "metrics", "stats", "statistics",
	"status", "health", "ping", "heartbeat",
	
	// Debug parameters
	"debug", "debug_mode", "debugMode", "test", "testing",
	"dev", "development", "stage", "staging",
	
	// API/Backend parameters
	"api", "api_key", "apikey", "secret", "token", "access_token",
	"key", "password", "passwd", "credential", "auth",
	
	// Configuration parameters
	"config", "configuration", "setting", "env", "environment",
	"profile", "mode",
	
	// Database parameters
	"db", "database", "sql", "connection", "conn",
	
	// File parameters
	"file", "path", "dir", "directory", "location",
	
	// Session parameters
	"session", "sid", "jsessionid", "phpsessid",
	
	// Output control
	"output", "format", "type", "callback", "jsonp",
	
	// Cache parameters
	"cache", "nocache", "timestamp",
}

// Common sensitive paths to check
var commonSensitivePaths = []string{
	"/admin", "/administrator", "/manager", "/login", "/logout",
	"/api", "/graphql", "/rest", "/soap", "/xmlrpc",
	"/debug", "/console", "/terminal", "/shell",
	"/logs", "/log", "/logging", "/trace",
	"/config", "/configuration", "/settings",
	"/backup", "/dump", "/export", "/import",
	"/test", "/testing", "/dev", "/development",
	"/monitor", "/status", "/health", "/metrics",
	"/phpmyadmin", "/adminer", "/webadmin",
	"/.git", "/svn", "/cvs",
	"/wp-admin", "/wp-login.php",
	"/jenkins", "/jenkins/script",
	"/actuator", "/actuator/health", "/actuator/info",
	"/_search", "/_cat", "/_nodes", // Elasticsearch
	"/phpinfo.php", "/info.php",
	"/robots.txt", "/sitemap.xml",
	"/crossdomain.xml", "/clientaccesspolicy.xml",
}

func main() {
	config := parseFlags()
	
	spider := NewSpider(config)
	defer spider.Close()
	
	fmt.Printf("[*] Starting spider on: %s\n", config.URL)
	fmt.Printf("[*] Max Depth: %d\n", config.MaxDepth)
	fmt.Printf("[*] Concurrent workers: %d\n", config.MaxConcurrent)
	fmt.Printf("[*] Timeout: %d seconds\n", config.Timeout)
	
	spider.Run()
	spider.PrintResults()
	spider.SaveResults()
}

func parseFlags() Config {
	var config Config
	
	flag.StringVar(&config.URL, "u", "", "Target URL (required)")
	flag.IntVar(&config.MaxDepth, "d", 3, "Maximum crawling depth")
	flag.IntVar(&config.MaxConcurrent, "c", 10, "Maximum concurrent requests")
	flag.IntVar(&config.Timeout, "t", 30, "Request timeout in seconds")
	flag.StringVar(&config.UserAgent, "a", "Mozilla/5.0 (compatible; SpiderBot/1.0)", "User-Agent string")
	flag.StringVar(&config.OutputFile, "o", "spider_results.txt", "Output file")
	flag.BoolVar(&config.UseHeaders, "headers", true, "Check for parameters in headers")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
	
	flag.Parse()
	
	if config.URL == "" {
		fmt.Println("Error: URL is required")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(1)
	}
	
	return config
}

func NewSpider(config Config) *Spider {
	// Configure HTTP client with timeout and TLS config
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Allow self-signed certs
			},
		},
	}
	
	return &Spider{
		config:         config,
		client:         client,
		visited:        make(map[string]bool),
		commonParams:   commonLogParams,
		sensitivePaths: commonSensitivePaths,
		queue:          make(chan Task, 1000),
	}
}

func (s *Spider) Close() {
	close(s.queue)
}

func (s *Spider) Run() {
	// Start worker goroutines
	for i := 0; i < s.config.MaxConcurrent; i++ {
		go s.worker()
	}
	
	// Seed the queue with initial URL
	s.wg.Add(1)
	s.queue <- Task{URL: s.config.URL, Depth: 0}
	
	s.wg.Wait()
}

func (s *Spider) worker() {
	for task := range s.queue {
		s.processTask(task)
		s.wg.Done()
	}
}

func (s *Spider) processTask(task Task) {
	// Check if we've already visited this URL
	s.visitedMutex.RLock()
	if s.visited[task.URL] {
		s.visitedMutex.RUnlock()
		return
	}
	s.visitedMutex.RUnlock()
	
	// Mark as visited
	s.visitedMutex.Lock()
	s.visited[task.URL] = true
	s.visitedMutex.Unlock()
	
	if s.config.Verbose {
		fmt.Printf("[+] Crawling: %s (Depth: %d)\n", task.URL, task.Depth)
	}
	
	// Fetch the page
	resp, err := s.fetch(task.URL)
	if err != nil {
		if s.config.Verbose {
			fmt.Printf("[-] Error fetching %s: %v\n", task.URL, err)
		}
		return
	}
	defer resp.Body.Close()
	
	// Analyze current URL for parameters
	s.analyzeURL(resp)
	
	// Analyze response headers for sensitive information
	if s.config.UseHeaders {
		s.analyzeHeaders(resp.Request.URL.String(), resp.Header)
	}
	
	// If we haven't reached max depth, extract and queue links
	if task.Depth < s.config.MaxDepth {
		// Read the response body once for analysis and link extraction
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			if s.config.Verbose {
				fmt.Printf("[-] Error reading body from %s: %v\n", task.URL, err)
			}
			return
		}
		
		// Analyze response body
		s.analyzeResponseBody(resp.Request.URL.String(), bodyBytes)
		
		// Extract links from the body
		bodyReader := strings.NewReader(string(bodyBytes))
		links := s.extractLinks(bodyReader, task.URL)
		
		for _, link := range links {
			s.visitedMutex.RLock()
			visited := s.visited[link]
			s.visitedMutex.RUnlock()
			
			if !visited {
				s.wg.Add(1)
				s.queue <- Task{URL: link, Depth: task.Depth + 1}
			}
		}
	}
}

func (s *Spider) fetch(urlStr string) (*http.Response, error) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("User-Agent", s.config.UserAgent)
	
	// Add common headers that might reveal parameters
	if s.config.UseHeaders {
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		req.Header.Set("X-Real-IP", "127.0.0.1")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	}
	
	return s.client.Do(req)
}

func (s *Spider) analyzeURL(resp *http.Response) {
	urlStr := resp.Request.URL.String()
	parsedURL, err := urlme.Parse(urlStr)
	if err != nil {
		return
	}
	
	// Check for sensitive paths
	for _, path := range s.sensitivePaths {
		if strings.Contains(parsedURL.Path, path) {
			s.addResult(Result{
				URL:        urlStr,
				Type:       "Sensitive Path",
				Parameter:  "Path",
				Value:      parsedURL.Path,
				Confidence: "High",
				Source:     "URL Path",
			})
		}
	}
	
	// Analyze query parameters
	query := parsedURL.Query()
	for param, values := range query {
		// Check if parameter matches common logging/backend patterns
		for _, commonParam := range s.commonParams {
			if strings.Contains(strings.ToLower(param), strings.ToLower(commonParam)) {
				for _, value := range values {
					s.addResult(Result{
						URL:        urlStr,
						Type:       "Sensitive Parameter",
						Parameter:  param,
						Value:      value,
						Confidence: "Medium",
						Source:     "Query Parameter",
					})
				}
			}
		}
		
		// Check for common debug values
		for _, value := range values {
			lowerValue := strings.ToLower(value)
			if strings.Contains(lowerValue, "debug") ||
				strings.Contains(lowerValue, "true") ||
				strings.Contains(lowerValue, "on") ||
				strings.Contains(lowerValue, "1") ||
				strings.Contains(lowerValue, "enable") {
				s.addResult(Result{
					URL:        urlStr,
					Type:       "Debug Parameter",
					Parameter:  param,
					Value:      value,
					Confidence: "Low",
					Source:     "Query Parameter Value",
				})
			}
		}
	}
}

func (s *Spider) analyzeHeaders(urlStr string, headers http.Header) {
	sensitiveHeaders := []string{
		"X-Debug", "X-Debug-Mode", "X-Debug-Enabled",
		"X-API-Key", "X-Api-Key", "X-Secret",
		"X-Token", "X-Access-Token",
		"Debug", "Debug-Mode",
		"X-Log-Level", "X-Logging",
		"X-Admin", "X-Administrator",
	}
	
	for header, values := range headers {
		lowerHeader := strings.ToLower(header)
		for _, sensitive := range sensitiveHeaders {
			if strings.Contains(lowerHeader, strings.ToLower(sensitive)) {
				for _, value := range values {
					s.addResult(Result{
						URL:        urlStr,
						Type:       "Sensitive Header",
						Parameter:  header,
						Value:      value,
						Confidence: "High",
						Source:     "Response Header",
					})
				}
			}
		}
	}
}

func (s *Spider) analyzeResponseBody(urlStr string, body []byte) {
	bodyStr := string(body)
	
	// Look for common patterns in JavaScript
	jsPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(debug|log|verbose)\s*[:=]\s*(true|1|"true")`),
		regexp.MustCompile(`(?i)console\.(log|debug|info|warn|error)`),
		regexp.MustCompile(`(?i)localStorage\.getItem\(["'](debug|log)["']\)`),
		regexp.MustCompile(`(?i)debugger`),
	}
	
	for _, pattern := range jsPatterns {
		if pattern.MatchString(bodyStr) {
			s.addResult(Result{
				URL:        urlStr,
				Type:       "Debug Code",
				Parameter:  "JavaScript Pattern",
				Value:      pattern.String(),
				Confidence: "Low",
				Source:     "Response Body",
			})
		}
	}
	
	// Look for HTML comments with sensitive info
	htmlCommentRegex := regexp.MustCompile(`<!--\s*(.*?)\s*-->`)
	comments := htmlCommentRegex.FindAllStringSubmatch(bodyStr, -1)
	for _, comment := range comments {
		if len(comment) > 1 {
			lowerComment := strings.ToLower(comment[1])
			for _, param := range s.commonParams {
				if strings.Contains(lowerComment, strings.ToLower(param)) {
					s.addResult(Result{
						URL:        urlStr,
						Type:       "Sensitive Comment",
						Parameter:  "HTML Comment",
						Value:      comment[1],
						Confidence: "Medium",
						Source:     "Response Body",
					})
					break
				}
			}
		}
	}
	
	// Look for hidden form fields
	hiddenFieldRegex := regexp.MustCompile(`<input[^>]*type=["']hidden["'][^>]*name=["']([^"']+)["'][^>]*>`)
	hiddenFields := hiddenFieldRegex.FindAllStringSubmatch(bodyStr, -1)
	for _, field := range hiddenFields {
		if len(field) > 1 {
			for _, param := range s.commonParams {
				if strings.Contains(strings.ToLower(field[1]), strings.ToLower(param)) {
					s.addResult(Result{
						URL:        urlStr,
						Type:       "Hidden Field",
						Parameter:  field[1],
						Value:      "Hidden Input",
						Confidence: "Medium",
						Source:     "Response Body",
					})
					break
				}
			}
		}
	}
}

func (s *Spider) extractLinks(body io.Reader, baseURL string) []string {
	var links []string
	base, err := urlme.Parse(baseURL)
	if err != nil {
		return links
	}
	
	tokenizer := html.NewTokenizer(body)
	for {
		tokenType := tokenizer.Next()
		switch tokenType {
		case html.ErrorToken:
			return links
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			if token.Data == "a" {
				for _, attr := range token.Attr {
					if attr.Key == "href" {
						link, err := urlme.Parse(attr.Val)
						if err != nil {
							continue
						}
						absoluteURL := base.ResolveReference(link).String()
						if s.isValidURL(absoluteURL) && strings.HasPrefix(absoluteURL, base.Scheme+"://"+base.Host) {
							links = append(links, absoluteURL)
						}
					}
				}
			} else if token.Data == "form" {
				for _, attr := range token.Attr {
					if attr.Key == "action" {
						link, err := urlme.Parse(attr.Val)
						if err != nil {
							continue
						}
						absoluteURL := base.ResolveReference(link).String()
						if s.isValidURL(absoluteURL) && strings.HasPrefix(absoluteURL, base.Scheme+"://"+base.Host) {
							links = append(links, absoluteURL)
						}
					}
				}
			}
		}
	}
}

func (s *Spider) isValidURL(urlStr string) bool {
	u, err := urlme.Parse(urlStr)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func (s *Spider) addResult(result Result) {
	s.resultsMutex.Lock()
	s.results = append(s.results, result)
	s.resultsMutex.Unlock()
	
	fmt.Printf("[!] Found: %s - %s: %s=%s (Confidence: %s)\n",
		result.Type, result.URL, result.Parameter, result.Value, result.Confidence)
}

func (s *Spider) PrintResults() {
	fmt.Printf("\n=== SPIDER RESULTS ===\n")
	fmt.Printf("Total findings: %d\n\n", len(s.results))
	
	for _, result := range s.results {
		fmt.Printf("Type: %s\n", result.Type)
		fmt.Printf("URL: %s\n", result.URL)
		fmt.Printf("Parameter: %s\n", result.Parameter)
		fmt.Printf("Value: %s\n", result.Value)
		fmt.Printf("Confidence: %s\n", result.Confidence)
		fmt.Printf("Source: %s\n", result.Source)
		fmt.Println("---")
	}
}

func (s *Spider) SaveResults() {
	file, err := os.Create(s.config.OutputFile)
	if err != nil {
		fmt.Printf("[-] Error creating output file: %v\n", err)
		return
	}
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	
	writer.WriteString(fmt.Sprintf("Spider Results - %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString(fmt.Sprintf("Target: %s\n", s.config.URL))
	writer.WriteString(fmt.Sprintf("Total findings: %d\n\n", len(s.results)))
	
	for _, result := range s.results {
		writer.WriteString(fmt.Sprintf("Type: %s\n", result.Type))
		writer.WriteString(fmt.Sprintf("URL: %s\n", result.URL))
		writer.WriteString(fmt.Sprintf("Parameter: %s\n", result.Parameter))
		writer.WriteString(fmt.Sprintf("Value: %s\n", result.Value))
		writer.WriteString(fmt.Sprintf("Confidence: %s\n", result.Confidence))
		writer.WriteString(fmt.Sprintf("Source: %s\n", result.Source))
		writer.WriteString("---\n")
	}
	
	writer.Flush()
	fmt.Printf("[*] Results saved to: %s\n", s.config.OutputFile)
}
