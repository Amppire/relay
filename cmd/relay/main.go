package main

import (
	"flag"
	"log"
	"os"

	"github.com/relay/relay/internal/app"
)

func main() {
	port := flag.String("port", "8080", "Port to listen on")
	dbPath := flag.String("db", "relay.db", "SQLite database path")
	baseURL := flag.String("base-url", "", "Default public base URL")
	flag.Parse()

	if envPort := os.Getenv("PORT"); envPort != "" {
		*port = envPort
	}
	if envDB := os.Getenv("DATABASE_PATH"); envDB != "" {
		*dbPath = envDB
	}

	cfg := app.Config{
		Port:           *port,
		DBPath:         *dbPath,
		DefaultBaseURL: *baseURL,
	}

	if err := app.RunServer(cfg); err != nil {
		log.Fatalf("Server exited with error: %v", err)
	}
}
