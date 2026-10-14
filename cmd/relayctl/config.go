package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Profile struct {
	Endpoint string `json:"endpoint"`
	APIKey   string `json:"api_key,omitempty"`
}

type CLIConfig struct {
	CurrentProfile string             `json:"current_profile"`
	Profiles       map[string]Profile `json:"profiles"`
}

func configFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".relay")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func loadCLIConfig() (*CLIConfig, error) {
	path, err := configFilePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &CLIConfig{
				CurrentProfile: "default",
				Profiles: map[string]Profile{
					"default": {
						Endpoint: "http://localhost:8080",
					},
				},
			}, nil
		}
		return nil, err
	}

	var cfg CLIConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func saveCLIConfig(cfg *CLIConfig) error {
	path, err := configFilePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// ResolveTarget determines endpoint and API key using strict precedence:
// 1. Explicit CLI flags
// 2. Environment variables (RELAY_ENDPOINT, RELAY_API_KEY)
// 3. Active configuration profile (~/.relay/config.json)
// 4. Default fallback (http://localhost:8080)
func ResolveTarget(flagEndpoint, flagToken string) (string, string) {
	endpoint := flagEndpoint
	token := flagToken

	if endpoint == "" {
		endpoint = os.Getenv("RELAY_ENDPOINT")
	}
	if token == "" {
		token = os.Getenv("RELAY_API_KEY")
	}

	if endpoint == "" || token == "" {
		cfg, err := loadCLIConfig()
		if err == nil {
			if prof, ok := cfg.Profiles[cfg.CurrentProfile]; ok {
				if endpoint == "" && prof.Endpoint != "" {
					endpoint = prof.Endpoint
				}
				if token == "" && prof.APIKey != "" {
					token = prof.APIKey
				}
			}
		}
	}

	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	return endpoint, token
}

func runConfigCmd(args []string) {
	if len(args) < 1 {
		fmt.Println(`Usage:
  relayctl config get
  relayctl config set-endpoint <url>
  relayctl config set-token <token>
  relayctl config use-profile <profile_name>`)
		return
	}

	cfg, err := loadCLIConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	switch args[0] {
	case "get":
		prof := cfg.Profiles[cfg.CurrentProfile]
		fmt.Printf("Current Profile: %s\n", cfg.CurrentProfile)
		fmt.Printf("Endpoint:        %s\n", prof.Endpoint)
		hasToken := "no"
		if prof.APIKey != "" {
			hasToken = "yes (configured)"
		}
		fmt.Printf("API Key:         %s\n", hasToken)

	case "set-endpoint":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Error: missing endpoint URL")
			os.Exit(1)
		}
		prof := cfg.Profiles[cfg.CurrentProfile]
		prof.Endpoint = args[1]
		cfg.Profiles[cfg.CurrentProfile] = prof
		_ = saveCLIConfig(cfg)
		fmt.Printf("Updated [%s] endpoint -> %s\n", cfg.CurrentProfile, args[1])

	case "set-token":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Error: missing API token")
			os.Exit(1)
		}
		prof := cfg.Profiles[cfg.CurrentProfile]
		prof.APIKey = args[1]
		cfg.Profiles[cfg.CurrentProfile] = prof
		_ = saveCLIConfig(cfg)
		fmt.Printf("Updated [%s] API token.\n", cfg.CurrentProfile)

	case "use-profile":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "Error: missing profile name")
			os.Exit(1)
		}
		cfg.CurrentProfile = args[1]
		if _, ok := cfg.Profiles[cfg.CurrentProfile]; !ok {
			cfg.Profiles[cfg.CurrentProfile] = Profile{Endpoint: "http://localhost:8080"}
		}
		_ = saveCLIConfig(cfg)
		fmt.Printf("Switched to profile: %s\n", cfg.CurrentProfile)

	default:
		fmt.Fprintf(os.Stderr, "Unknown config subcommand: %s\n", args[0])
		os.Exit(1)
	}
}
