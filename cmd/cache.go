// Package cmd implements the CLI commands for argus.
package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sentiolabs/argus/internal/cache"
	"github.com/sentiolabs/argus/internal/config"
)

var (
	cacheProviderFlag string
	cacheClearAll     bool
)

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage the vulnerability cache",
}

var cacheRefreshCmd = &cobra.Command{
	Use:   "refresh",
	Short: "Refresh the vulnerability cache from providers",
	RunE:  runCacheRefresh,
}

var cacheStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the current state of the vulnerability cache",
	RunE:  runCacheStatus,
}

var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear the vulnerability cache",
	RunE:  runCacheClear,
}

func init() {
	rootCmd.AddCommand(cacheCmd)
	cacheCmd.AddCommand(cacheRefreshCmd)
	cacheCmd.AddCommand(cacheStatusCmd)
	cacheCmd.AddCommand(cacheClearCmd)

	cacheRefreshCmd.Flags().StringVar(&cacheProviderFlag, "provider", "all", "provider to refresh: all, snyk, or github")
	cacheClearCmd.Flags().BoolVar(&cacheClearAll, "all", false, "clear all projects' data")
}

func runCacheRefresh(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	mgr, err := cache.NewManager(cache.DefaultTTL, GetVerbose())
	if err != nil {
		return fmt.Errorf("failed to create cache manager: %w", err)
	}
	defer mgr.Close() //nolint:errcheck

	if err := mgr.Refresh(ctx, cfg, cacheProviderFlag, GetVerbose()); err != nil {
		return fmt.Errorf("cache refresh failed: %w", err)
	}

	count, err := mgr.Store().ProjectCount(ctx, mgr.ProjectKey())
	if err != nil {
		return fmt.Errorf("failed to get cache count: %w", err)
	}

	fmt.Printf("Cache refreshed: %d vulnerabilities cached for project %s\n", count, mgr.ProjectKey())
	return nil
}

func runCacheStatus(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	mgr, err := cache.NewManager(cache.DefaultTTL, GetVerbose())
	if err != nil {
		return fmt.Errorf("failed to create cache manager: %w", err)
	}
	defer mgr.Close() //nolint:errcheck

	store := mgr.Store()
	projectKey := mgr.ProjectKey()

	projectCount, err := store.ProjectCount(ctx, projectKey)
	if err != nil {
		return fmt.Errorf("failed to get project count: %w", err)
	}

	totalCount, err := store.TotalCount(ctx)
	if err != nil {
		return fmt.Errorf("failed to get total count: %w", err)
	}

	providers, err := store.GetMeta(projectKey, "providers")
	if err != nil {
		return fmt.Errorf("failed to get providers metadata: %w", err)
	}

	fetchedAt, err := store.GetMeta(projectKey, "fetched_at")
	if err != nil {
		return fmt.Errorf("failed to get fetched_at metadata: %w", err)
	}

	fmt.Printf("Project:             %s\n", projectKey)
	fmt.Printf("Database path:       %s\n", mgr.DBPathValue())
	fmt.Printf("Cached count:        %d (this project)\n", projectCount)
	fmt.Printf("Total count:         %d (all projects)\n", totalCount)

	if providers != "" {
		fmt.Printf("Providers:           %s\n", providers)
	} else {
		fmt.Printf("Providers:           (none)\n")
	}

	if fetchedAt != "" {
		t, err := time.Parse(time.RFC3339, fetchedAt)
		if err != nil {
			fmt.Printf("Fetched:             %s\n", fetchedAt)
		} else {
			ago := time.Since(t).Round(time.Second)
			fmt.Printf("Fetched:             %s (%s ago)\n", t.Local().Format(time.RFC3339), ago)
		}

		ttlStatus := "valid"
		if !mgr.IsValid() {
			ttlStatus = "expired"
		}
		fmt.Printf("TTL:                 %s (%s)\n", cache.DefaultTTL, ttlStatus)
	} else {
		fmt.Printf("Fetched:             (never)\n")
		fmt.Printf("TTL:                 %s (expired)\n", cache.DefaultTTL)
	}

	return nil
}

func runCacheClear(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	mgr, err := cache.NewManager(cache.DefaultTTL, GetVerbose())
	if err != nil {
		return fmt.Errorf("failed to create cache manager: %w", err)
	}
	defer mgr.Close() //nolint:errcheck

	if cacheClearAll {
		if err := mgr.Store().Clear(ctx, ""); err != nil {
			return fmt.Errorf("failed to clear all cache: %w", err)
		}
		fmt.Println("Cache cleared for all projects.")
	} else {
		projectKey := mgr.ProjectKey()
		if err := mgr.Store().Clear(ctx, projectKey); err != nil {
			return fmt.Errorf("failed to clear cache for project %s: %w", projectKey, err)
		}
		fmt.Printf("Cache cleared for project: %s\n", projectKey)
	}

	return nil
}
