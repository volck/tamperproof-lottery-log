package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var witnessAlertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "Check security alerts from the server",
	Long: `Query the server for security alerts such as duplicate draw attempts.
Witnesses can use this to monitor for suspicious activity.`,
	RunE: runWitnessAlerts,
}

var alertsSince string

func init() {
	witnessCmd.AddCommand(witnessAlertsCmd)
	witnessAlertsCmd.Flags().StringVar(&alertsSince, "since", "", "Show alerts since timestamp (RFC3339 format)")
	witnessAlertsCmd.Flags().String("witness-id", "", "Your witness identifier (required)")
	witnessAlertsCmd.MarkFlagRequired("witness-id")
}

func runWitnessAlerts(cmd *cobra.Command, args []string) error {
	serverURL := viper.GetString("server")
	if serverURL == "" {
		return fmt.Errorf("server URL not configured")
	}

	// Get witness ID
	witnessID, err := cmd.Flags().GetString("witness-id")
	if err != nil || witnessID == "" {
		return fmt.Errorf("witness-id is required")
	}

	dataDir := getDataDir()

	// Create authenticated client
	client, _, tokenManager, err := createAuthenticatedClient(witnessID, serverURL, dataDir)
	if err != nil {
		return fmt.Errorf("failed to create authenticated client: %w", err)
	}

	if tokenManager != nil {
		defer tokenManager.Stop()
	}

	// Build URL with optional since parameter
	url := fmt.Sprintf("%s/api/witness/alerts", serverURL)
	if alertsSince != "" {
		url = fmt.Sprintf("%s?since=%s", url, alertsSince)
	}

	// Get token
	token := ""
	if tokenManager != nil {
		token = tokenManager.GetToken()
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to query alerts: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var result struct {
		Alerts []struct {
			Timestamp   time.Time `json:"timestamp"`
			AlertType   string    `json:"alert_type"`
			SeqNo       int       `json:"seqno,omitempty"`
			Source      string    `json:"source"`
			UserEmail   string    `json:"user_email,omitempty"`
			Description string    `json:"description"`
		} `json:"alerts"`
		Count int `json:"count"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if result.Count == 0 {
		fmt.Println("No security alerts found.")
		return nil
	}

	fmt.Printf("Found %d security alert(s):\n\n", result.Count)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIMESTAMP\tTYPE\tSEQNO\tUSER\tSOURCE\tDESCRIPTION")
	fmt.Fprintln(w, "---------\t----\t-----\t----\t------\t-----------")

	for _, alert := range result.Alerts {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\n",
			alert.Timestamp.Format("2006-01-02 15:04:05"),
			alert.AlertType,
			alert.SeqNo,
			alert.UserEmail,
			alert.Source,
			alert.Description,
		)
	}
	w.Flush()

	return nil
}
