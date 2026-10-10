package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/relay/relay/internal/app"
	"github.com/relay/relay/internal/core/domain"
	"github.com/relay/relay/internal/core/services"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "server":
		runServerCmd(os.Args[2:])
	case "shorten":
		runShortenCmd(os.Args[2:])
	case "paste":
		runPasteCmd(os.Args[2:])
	case "keys":
		runKeysCmd(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Relay - Programmable, capability-governed secure sharing

Usage:
  relayctl <command> [options]

Commands:
  server       Start the Relay HTTP server
  shorten      Create a new shortened link
  paste        Share text, markdown, or code with an expiring link
  keys         Manage API keys

Run 'relayctl <command> --help' for details on specific commands.`)
}

func runServerCmd(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	port := fs.String("port", "8080", "Port to listen on")
	dbPath := fs.String("db", "relay.db", "SQLite database path")
	baseURL := fs.String("base-url", "", "Default public base URL")
	_ = fs.Parse(args)

	cfg := app.Config{
		Port:           *port,
		DBPath:         *dbPath,
		DefaultBaseURL: *baseURL,
	}

	if err := app.RunServer(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runShortenCmd(args []string) {
	fs := flag.NewFlagSet("shorten", flag.ExitOnError)
	slug := fs.String("slug", "", "Custom slug")
	endpoint := fs.String("endpoint", "http://localhost:8080", "Relay server address")
	token := fs.String("token", "", "API key (optional)")
	expire := fs.String("expire", "", "Expiration duration (e.g. 1h, 24h, 7d)")
	maxAccesses := fs.Int64("max", 0, "Maximum allowed clicks")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: missing target destination URL.")
		fmt.Fprintln(os.Stderr, "Usage: relayctl shorten <destination_url> [--slug=<custom>] [--expire=24h]")
		os.Exit(1)
	}

	destURL := fs.Arg(0)
	var expiresAt *time.Time
	if *expire != "" {
		d, err := parseDuration(*expire)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --expire duration: %v\n", err)
			os.Exit(1)
		}
		t := time.Now().UTC().Add(d)
		expiresAt = &t
	}

	var maxAcc *int64
	if *maxAccesses > 0 {
		maxAcc = maxAccesses
	}

	reqPayload := services.CreateLinkRequest{
		DestinationURL: destURL,
		Slug:           *slug,
		ExpiresAt:      expiresAt,
		MaxAccesses:    maxAcc,
		PreserveQuery:  true,
	}

	data, err := json.Marshal(reqPayload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encode request: %v\n", err)
		os.Exit(1)
	}

	url := strings.TrimRight(*endpoint, "/") + "/api/v1/links"
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to Relay server: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		fmt.Fprintf(os.Stderr, "Server returned error (HTTP %d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	var created services.CreateLinkResponse
	if err := json.Unmarshal(body, &created); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse response: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(created.URL)
}

func runPasteCmd(args []string) {
	fs := flag.NewFlagSet("paste", flag.ExitOnError)
	title := fs.String("title", "", "Optional title")
	format := fs.String("format", "plaintext", "Format: plaintext, markdown, code")
	lang := fs.String("lang", "", "Language for code highlighting (e.g. go, python, json)")
	slug := fs.String("slug", "", "Custom slug")
	endpoint := fs.String("endpoint", "http://localhost:8080", "Relay server address")
	token := fs.String("token", "", "API key (optional)")
	expire := fs.String("expire", "", "Expiration duration (e.g. 1h, 24h, 7d)")
	maxAccesses := fs.Int64("max", 0, "Maximum allowed views")
	_ = fs.Parse(args)

	var content string
	if fs.NArg() > 0 {
		filePath := fs.Arg(0)
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", filePath, err)
			os.Exit(1)
		}
		content = string(data)
		if *title == "" {
			*title = filePath
		}
	} else {
		// Read from stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			fmt.Fprintln(os.Stderr, "Error: missing input file or piped stdin.")
			fmt.Fprintln(os.Stderr, "Usage: relayctl paste <file> [--format=code] [--lang=go]")
			os.Exit(1)
		}
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
		content = string(data)
	}

	var expiresAt *time.Time
	if *expire != "" {
		d, err := parseDuration(*expire)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --expire duration: %v\n", err)
			os.Exit(1)
		}
		t := time.Now().UTC().Add(d)
		expiresAt = &t
	}

	var maxAcc *int64
	if *maxAccesses > 0 {
		maxAcc = maxAccesses
	}

	reqPayload := services.CreatePasteRequest{
		Content:     content,
		Title:       *title,
		Format:      domain.PasteFormat(*format),
		Language:    *lang,
		Slug:        *slug,
		ExpiresAt:   expiresAt,
		MaxAccesses: maxAcc,
		LineNumbers: true,
		RawEnabled:  true,
	}

	data, err := json.Marshal(reqPayload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encode request: %v\n", err)
		os.Exit(1)
	}

	url := strings.TrimRight(*endpoint, "/") + "/api/v1/pastes"
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to Relay server: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		fmt.Fprintf(os.Stderr, "Server returned error (HTTP %d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	var created services.CreatePasteResponse
	if err := json.Unmarshal(body, &created); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse response: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Link: %s\nRaw:  %s\n", created.URL, created.RawURL)
}

func runKeysCmd(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: relayctl keys <create|list>")
		os.Exit(1)
	}

	sub := args[0]
	switch sub {
	case "create":
		fs := flag.NewFlagSet("keys create", flag.ExitOnError)
		name := fs.String("name", "cli-key", "Name of the API key")
		scopes := fs.String("scopes", "*", "Comma-separated scopes")
		endpoint := fs.String("endpoint", "http://localhost:8080", "Relay server address")
		_ = fs.Parse(args[1:])

		scopeList := strings.Split(*scopes, ",")
		payload, _ := json.Marshal(services.CreateAPIKeyRequest{
			Name:   *name,
			Scopes: scopeList,
		})

		url := strings.TrimRight(*endpoint, "/") + "/api/v1/api-keys"
		resp, err := http.Post(url, "application/json", bytes.NewReader(payload))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusCreated {
			fmt.Fprintf(os.Stderr, "Failed to create API key (HTTP %d): %s\n", resp.StatusCode, string(body))
			os.Exit(1)
		}

		var created services.CreateAPIKeyResponse
		_ = json.Unmarshal(body, &created)

		fmt.Println("API key created successfully!")
		fmt.Println("Token (save this now, it cannot be shown again):")
		fmt.Printf("  %s\n\n", created.Token)
		fmt.Printf("Prefix: %s | Scopes: %v\n", created.KeyPrefix, created.Scopes)

	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", sub)
		os.Exit(1)
	}
}

func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		var days int
		if _, err := fmt.Sscanf(daysStr, "%d", &days); err == nil {
			return time.Duration(days) * 24 * time.Hour, nil
		}
	}
	return time.ParseDuration(s)
}
