package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Constants
const (
	CacheDir            = "Caches"
	JSFilesDirBase      = "JSFiles"
	DefaultTimeout      = 5 * time.Second
	DefaultEntropyThreshold = 4.5
)

var (
	DefaultUserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
	}

	Patterns = map[string]string{
		"API Key":              `(api_key|apiKey|apikey|client_id|clientId|access_token|token|apiToken)[\s]*[:=][\s]*['"]([a-zA-Z0-9-_]{32,})['"]`,
		"AWS Access Key":       `AKIA[0-9A-Z]{16}`,
		"AWS Secret Access Key": `aws_secret_access_key[\s]*[:=][\s]*['"]([a-zA-Z0-9/+=]{40,})['"]`,
		"GitHub Token":         `gh[pousr]_[0-9a-zA-Z]{36}`,
		"Slack Token":          `xox[baprs]-[0-9a-zA-Z]{10,}`,
		"Stripe Key":           `(sk_live|pk_live)_[0-9a-zA-Z]{24}`,
		"JWT Token":            `eyJ[0-9A-Za-z-_]+\.[0-9A-Za-z-_]+\.[0-9A-Za-z-_]{43,}`,
		"Database Connection":  `(mongodb:\/\/|mysql:\/\/|postgres:\/\/|redis:\/\/|sqlite:\/\/)[^\s'"]+`,
		"Private Key":          `-----BEGIN (RSA|EC|DSA|PRIVATE) KEY-----([^\-]+)-----END (RSA|EC|DSA|PRIVATE) KEY-----`,
		"High Entropy String":  `[A-Za-z0-9+/]{40,}`,
		"Password":             `(password|pass|pwd|passwd)[\s]*[:=][\s]*['"]([^\s'"]{8,})['"]`,
	}
)

// Utility functions

func calculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}
	entropy := 0.0
	for _, x := range uniqueChars(data) {
		p_x := float64(strings.Count(data, string(x))) / float64(len(data))
		entropy += -p_x * math.Log2(p_x)
	}
	return entropy
}

func uniqueChars(s string) []rune {
	seen := make(map[rune]bool)
	result := []rune{}
	for _, char := range s {
		if !seen[char] {
			seen[char] = true
			result = append(result, char)
		}
	}
	return result
}

func isHighEntropyString(s string, threshold float64) bool {
	return calculateEntropy(s) > threshold
}

func fetchPage(url string, timeout time.Duration, userAgent string) (string, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func extractJSFiles(html, baseURL string) []string {
	re := regexp.MustCompile(`<script.*?src=["'](.*?)["'].*?>`)
	matches := re.FindAllStringSubmatch(html, -1)
	jsFiles := make([]string, 0, len(matches))
	for _, match := range matches {
		jsFile := match[1]
		if !strings.HasPrefix(jsFile, "http") {
			jsFile = baseURL + jsFile
		}
		jsFiles = append(jsFiles, jsFile)
	}
	return jsFiles
}

func detectObfuscation(jsCode string) []string {
	obfuscationIndicators := []string{
		`eval\(`, `document\.write\(`, `Function\(`, `atob\(`, `btoa\(`,
		`unescape\(`, `setTimeout\(`, `setInterval\(`, `\\x[a-fA-F0-9]{2}`,
		`(?:[\w\d_$]+\s*=\s*[\w\d_$]+\s*\+\s*){3,}`, `0x[0-9a-fA-F]+`,
	}
	findings := []string{}
	for _, pattern := range obfuscationIndicators {
		re := regexp.MustCompile(pattern)
		if re.MatchString(jsCode) {
			findings = append(findings, fmt.Sprintf("Obfuscation pattern detected: %s", pattern))
		}
	}
	return findings
}

func analyzeJS(jsURL string, patterns map[string]string, entropyThreshold float64) []map[string]string {
	jsCode, err := fetchPage(jsURL, DefaultTimeout, DefaultUserAgents[0])
	if err != nil {
		log.Printf("Error fetching %s: %v", jsURL, err)
		return nil
	}

	findings := []map[string]string{}
	obfuscationFindings := detectObfuscation(jsCode)
	for _, pattern := range obfuscationFindings {
		findings = append(findings, map[string]string{"Part": "Obfuscation Detected", "Details": pattern})
	}

	for key, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(jsCode, -1)
		if len(matches) > 0 {
			for _, match := range matches {
				findings = append(findings, map[string]string{"Part": key, "Details": strings.Join(match[1:], ", ")})
			}
		}
	}

	// Entropy-based detection
	re := regexp.MustCompile(`[A-Za-z0-9+/]{40,}`)
	matches := re.FindAllString(jsCode, -1)
	for _, match := range matches {
		if isHighEntropyString(match, entropyThreshold) {
			findings = append(findings, map[string]string{"Part": "High Entropy String", "Details": match})
		}
	}

	return findings
}

func cacheResults(url string, results map[string][]map[string]string) {
	if err := os.MkdirAll(CacheDir, os.ModePerm); err != nil {
		log.Printf("Error creating cache directory: %v", err)
		return
	}

	hostname := extractHostname(url)
	if hostname == "" {
		log.Printf("Invalid URL: %s", url)
		return
	}

	filename := strings.ReplaceAll(hostname, ".", "_") + ".json"
	filepath := filepath.Join(CacheDir, filename)

	file, err := os.Create(filepath)
	if err != nil {
		log.Printf("Error creating cache file: %v", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		log.Printf("Error encoding cache file: %v", err)
	}
}

func loadCachedResults(url string) map[string][]map[string]string {
	hostname := extractHostname(url)
	if hostname == "" {
		log.Printf("Invalid URL: %s", url)
		return nil
	}

	filename := strings.ReplaceAll(hostname, ".", "_") + ".json"
	filepath := filepath.Join(CacheDir, filename)

	file, err := os.Open(filepath)
	if err != nil {
		return nil
	}
	defer file.Close()

	var results map[string][]map[string]string
	if err := json.NewDecoder(file).Decode(&results); err != nil {
		log.Printf("Error decoding cache file: %v", err)
		return nil
	}
	return results
}

func extractHostname(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsedURL.Hostname()
}

func printResults(jsURL string, findings []map[string]string, filters []string) {
	fmt.Printf("\n[URL] %s\n", jsURL)
	if len(findings) > 0 {
		for _, finding := range findings {
			if filters == nil || contains(filters, finding["Part"]) {
				fmt.Printf("[%s] %s\n", finding["Part"], finding["Details"])
			}
		}
	} else {
		fmt.Println("[Credentials] Not Found")
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func downloadJS(jsURL, targetDir string) {
	if err := os.MkdirAll(targetDir, os.ModePerm); err != nil {
		log.Printf("Error creating target directory: %v", err)
		return
	}

	jsCode, err := fetchPage(jsURL, DefaultTimeout, DefaultUserAgents[0])
	if err != nil {
		log.Printf("Error fetching %s: %v", jsURL, err)
		return
	}

	filename := filepath.Join(targetDir, strings.ReplaceAll(url.PathEscape(jsURL), ".js")
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Error creating file: %v", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(jsCode); err != nil {
		log.Printf("Error writing to file: %v", err)
	}
}

func readListFromFile(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("File not found: %s", filename)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lines := []string{}
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func deepScan(urls []string, userAgents []string, useCache, download bool, timeout time.Duration, filters []string, entropyThreshold float64) {
	for _, url := range urls {
		hostname := extractHostname(url)
		if hostname == "" {
			fmt.Printf("Invalid URL: %s\n", url)
			continue
		}

		if useCache && !download {
			cachedResults := loadCachedResults(url)
			if cachedResults != nil {
				fmt.Println("[Cached Results]")
				for jsURL, findings := range cachedResults {
					printResults(jsURL, findings, filters)
				}
				continue
			}
		}

		baseURL := "https://" + hostname
		html, err := fetchPage(url, timeout, userAgents[0])
		if err != nil {
			continue
		}

		jsFiles := extractJSFiles(html, baseURL)
		fmt.Println("\n[ JS Files ]")
		for _, jsFile := range jsFiles {
			fmt.Printf("- %s\n", jsFile)
		}

		if len(jsFiles) == 0 {
			continue
		}

		results := make(map[string][]map[string]string)
		var wg sync.WaitGroup
		var mu sync.Mutex

		for _, jsFile := range jsFiles {
			wg.Add(1)
			go func(jsURL string) {
				defer wg.Done()
				findings := analyzeJS(jsURL, Patterns, entropyThreshold)
				mu.Lock()
				results[jsURL] = findings
				mu.Unlock()
				printResults(jsURL, findings, filters)
			}(jsFile)
		}

		wg.Wait()

		if download {
			targetDir := filepath.Join(JSFilesDirBase, hostname)
			for _, jsFile := range jsFiles {
				wg.Add(1)
				go func(jsURL string) {
					defer wg.Done()
					downloadJS(jsURL, targetDir)
				}(jsFile)
			}
			wg.Wait()
		}

		if useCache {
			cacheResults(url, results)
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <URL|URL list file> [--user-agent-file <file>] [--no-cache] [--download] [--timeout N] [--filter pattern1 pattern2 ...] [--entropy threshold]")
		os.Exit(1)
	}

	urlArg := os.Args[1]
	userAgentFile := ""
	noCache := false
	download := false
	timeout := DefaultTimeout
	var filters []string
	entropyThreshold := DefaultEntropyThreshold

	for i, arg := range os.Args {
		switch arg {
		case "--user-agent-file":
			userAgentFile = os.Args[i+1]
		case "--no-cache":
			noCache = true
		case "--download":
			download = true
		case "--timeout":
			timeout = time.Duration(atoi(os.Args[i+1])) * time.Second
		case "--filter":
			filters = os.Args[i+1 : i+6] // Extract up to 5 patterns to filter
		case "--entropy":
			entropyThreshold = atof(os.Args[i+1])
		}
	}

	urls := []string{urlArg}
	if _, err := os.Stat(urlArg); err == nil {
		urls = readListFromFile(urlArg)
	}

	userAgents := DefaultUserAgents
	if userAgentFile != "" {
		userAgents = readListFromFile(userAgentFile)
	}

	deepScan(urls, userAgents, !noCache, download, timeout, filters, entropyThreshold)
}

func atoi(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return i
}

func atof(s string) float64 {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0.0
	}
	return f
}