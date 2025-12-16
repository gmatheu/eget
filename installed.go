package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type InstalledEntry struct {
	Repo           string                 `toml:"repo"`
	Target         string                 `toml:"target"`
	InstalledAt    time.Time              `toml:"installed_at"`
	URL            string                 `toml:"url"`
	Asset          string                 `toml:"asset"`
	Tool           string                 `toml:"tool,omitempty"`
	ExtractedFiles []string               `toml:"extracted_files"`
	Options        map[string]interface{} `toml:"options"`
	Version        string                 `toml:"version,omitempty"`
}

type InstalledConfig struct {
	Installed map[string]InstalledEntry `toml:"installed"`
}

// getInstalledConfigPath returns the path to the installed packages config file
func getInstalledConfigPath() string {
	homePath, _ := os.UserHomeDir()

	// Use the same logic as existing config but for installed.toml
	configPath := filepath.Join(homePath, ".eget.installed.toml")

	// Check if it exists, if not try the XDG config directory
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		var configDir string
		switch runtime.GOOS {
		case "windows":
			configDir = os.Getenv("LOCALAPPDATA")
		default:
			configDir = os.Getenv("XDG_CONFIG_HOME")
		}
		if configDir == "" {
			configDir = filepath.Join(homePath, ".config")
		}
		xdgPath := filepath.Join(configDir, "eget", "installed.toml")
		return xdgPath
	}

	return configPath
}

// loadInstalledConfig loads the installed packages config from file
func loadInstalledConfig() (*InstalledConfig, error) {
	configPath := getInstalledConfigPath()

	var config InstalledConfig
	_, err := toml.DecodeFile(configPath, &config)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load installed config: %w", err)
	}

	if config.Installed == nil {
		config.Installed = make(map[string]InstalledEntry)
	}

	return &config, nil
}

// saveInstalledConfig saves the installed packages config to file
func saveInstalledConfig(config *InstalledConfig) error {
	configPath := getInstalledConfigPath()

	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	encoder := toml.NewEncoder(file)
	if err := encoder.Encode(config); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}

	return nil
}

// normalizeRepoName converts various target formats to a consistent repo key
func normalizeRepoName(target string) string {
	// Handle GitHub URLs
	if strings.Contains(target, "github.com/") {
		// Extract user/repo from github.com/user/repo or full URLs
		parts := strings.Split(target, "github.com/")
		if len(parts) > 1 {
			path := parts[1]
			// Remove trailing slashes and .git
			path = strings.TrimSuffix(path, "/")
			path = strings.TrimSuffix(path, ".git")
			// Take only user/repo part
			if idx := strings.Index(path, "/"); idx > 0 {
				repoPart := path[:idx+1+strings.Index(path[idx+1:], "/")]
				if repoPart == "" {
					repoPart = path
				}
				return strings.TrimSuffix(repoPart, "/")
			}
			return path
		}
	}

	// For direct repo names like "user/repo"
	if strings.Count(target, "/") == 1 && !strings.Contains(target, "://") {
		return target
	}

	// For other URLs or local paths, use as-is but clean up
	return strings.TrimSuffix(target, "/")
}

// extractOptionsMap converts Flags struct to a map for TOML storage
func extractOptionsMap(opts Flags) map[string]interface{} {
	options := make(map[string]interface{})

	// Only store meaningful options that affect installation
	if opts.Tag != "" {
		options["tag"] = opts.Tag
	}
	if opts.System != "" {
		options["system"] = opts.System
	}
	if opts.Output != "" {
		options["output"] = opts.Output
	}
	if opts.ExtractFile != "" {
		options["extract_file"] = opts.ExtractFile
	}
	if opts.All {
		options["all"] = opts.All
	}
	if opts.Quiet {
		options["quiet"] = opts.Quiet
	}
	if opts.DLOnly {
		options["download_only"] = opts.DLOnly
	}
	if opts.UpgradeOnly {
		options["upgrade_only"] = opts.UpgradeOnly
	}
	if len(opts.Asset) > 0 {
		options["asset"] = opts.Asset
	}
	if opts.Hash {
		options["hash"] = opts.Hash
	}
	if opts.Verify != "" {
		options["verify"] = opts.Verify
	}
	if opts.DisableSSL {
		options["disable_ssl"] = opts.DisableSSL
	}

	return options
}

// recordInstallation records a successful installation
func recordInstallation(target, url, tool string, opts Flags, extractedFiles []string) error {
	config, err := loadInstalledConfig()
	if err != nil {
		return err
	}

	repoKey := normalizeRepoName(target)

	entry := InstalledEntry{
		Repo:           repoKey,
		Target:         target,
		InstalledAt:    time.Now(),
		URL:            url,
		Asset:          filepath.Base(url),
		Tool:           tool,
		ExtractedFiles: extractedFiles,
		Options:        extractOptionsMap(opts),
	}

	// Store entry
	if config.Installed == nil {
		config.Installed = make(map[string]InstalledEntry)
	}
	config.Installed[repoKey] = entry

	return saveInstalledConfig(config)
}

// removeInstalled removes an installed package from tracking
func removeInstalled(target string) error {
	config, err := loadInstalledConfig()
	if err != nil {
		return err
	}

	repoKey := normalizeRepoName(target)
	delete(config.Installed, repoKey)

	return saveInstalledConfig(config)
}

// listInstalled displays all installed packages
func listInstalled() error {
	config, err := loadInstalledConfig()
	if err != nil {
		return err
	}

	if len(config.Installed) == 0 {
		fmt.Println("No packages installed.")
		return nil
	}

	fmt.Println("Installed packages:")
	fmt.Println()

	for _, entry := range config.Installed {
		fmt.Printf("%s\n", entry.Repo)
		fmt.Printf("  Target: %s\n", entry.Target)
		fmt.Printf("  Installed: %s\n", entry.InstalledAt.Format("2006-01-02 15:04:05"))
		if len(entry.ExtractedFiles) == 1 {
			fmt.Printf("  File: %s\n", entry.ExtractedFiles[0])
		} else {
			fmt.Printf("  Files: %s\n", strings.Join(entry.ExtractedFiles, ", "))
		}

		if len(entry.Options) > 0 {
			var opts []string
			for k, v := range entry.Options {
				opts = append(opts, fmt.Sprintf("%s=%v", k, v))
			}
			fmt.Printf("  Options: %s\n", strings.Join(opts, ", "))
		}
		fmt.Println()
	}

	return nil
}
