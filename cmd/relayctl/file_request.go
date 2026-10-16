package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/relay/relay/internal/core/services"
	"github.com/relay/relay/internal/platform/crypto"
)

func runFileCmd(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: relayctl file send <filepath> [--endpoint=url] [--token=key]")
		return
	}

	sub := args[0]
	switch sub {
	case "send":
		fs := flag.NewFlagSet("file send", flag.ExitOnError)
		endpoint := fs.String("endpoint", "", "Relay server address")
		token := fs.String("token", "", "API key (optional)")
		_ = fs.Parse(args[1:])

		if fs.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "Error: missing target file path")
			os.Exit(1)
		}

		filePath := fs.Arg(0)
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}

		// Encrypt locally
		aad := crypto.BuildAAD("", "file", crypto.CurrentCipherVersion)
		ciphertext, nonce, dek, err := crypto.EncryptPayload(data, aad)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Encryption failed: %v\n", err)
			os.Exit(1)
		}

		targetEndpoint, targetToken := ResolveTarget(*endpoint, *token)
		url := strings.TrimRight(targetEndpoint, "/") + "/api/v1/files"

		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(ciphertext))
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-Relay-Filename", filepath.Base(filePath))
		if targetToken != "" {
			req.Header.Set("Authorization", "Bearer "+targetToken)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Upload error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		var uploadResp map[string]any
		_ = json.Unmarshal(respBody, &uploadResp)

		keyFrag := crypto.EncodeKeyFragment(dek)
		fullURL := fmt.Sprintf("%s#%s", uploadResp["url"], keyFrag)
		fmt.Printf("File encrypted and uploaded!\nDownload URL: %s\nNonce: %s\n", fullURL, base64.StdEncoding.EncodeToString(nonce))

	default:
		fmt.Fprintf(os.Stderr, "Unknown file subcommand: %s\n", sub)
		os.Exit(1)
	}
}

func runRequestCmd(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: relayctl request secret --name 'Database Creds'")
		return
	}

	sub := args[0]
	switch sub {
	case "secret":
		fs := flag.NewFlagSet("request secret", flag.ExitOnError)
		name := fs.String("name", "Secure Secret Request", "Title for portal")
		endpoint := fs.String("endpoint", "", "Relay server address")
		token := fs.String("token", "", "API key (optional)")
		_ = fs.Parse(args[1:])

		// 1. Generate X25519 asymmetric keypair locally
		privKey, pubKey, err := crypto.GenerateAsymmetricKeyPair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Keygen error: %v\n", err)
			os.Exit(1)
		}

		targetEndpoint, targetToken := ResolveTarget(*endpoint, *token)
		url := strings.TrimRight(targetEndpoint, "/") + "/api/v1/requests"

		payload, _ := json.Marshal(services.CreateRequestPortalInput{
			PublicKey: pubKey,
			Title:     *name,
		})

		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		if targetToken != "" {
			req.Header.Set("Authorization", "Bearer "+targetToken)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Request portal error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		var portalResp map[string]string
		_ = json.Unmarshal(respBody, &portalResp)

		fmt.Printf("Secure collection portal created!\nShare URL:   %s\nPrivate Key: %s\n", portalResp["url"], privKey)
		fmt.Println("(Keep your private key safe; you will need it to decrypt the recipient's payload)")

	default:
		fmt.Fprintf(os.Stderr, "Unknown request subcommand: %s\n", sub)
		os.Exit(1)
	}
}
