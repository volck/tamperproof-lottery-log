package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"lottery-tlog/tlog"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:          "status",
	Short:        "Check the status of the lottery log",
	Long:         "Display current tree status including confirmed and unconfirmed draws. Use --server to check a remote server.",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		serverURL, _ := cmd.Flags().GetString("server")
		if serverURL != "" {
			return checkServerStatus(serverURL)
		}

		// Local status check
		return checkLocalStatus()
	},
}

func init() {
	statusCmd.Flags().String("server", "", "Server URL (e.g. https://localhost:8443) to check remote status")
	rootCmd.AddCommand(statusCmd)
}

func checkServerStatus(serverURL string) error {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(serverURL + "/api/status")
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned error: %d", resp.StatusCode)
	}

	type WitnessInfo struct {
		WitnessID       string    `json:"witness_id"`
		LastTreeSize    int64     `json:"last_tree_size"`
		LastSignatureAt time.Time `json:"last_signature_at"`
	}

	type WitnessStatus struct {
		*WitnessInfo
		Online           bool      `json:"online"`
		LastHeartbeat    time.Time `json:"last_heartbeat,omitempty"`
		SecondsSinceHB   int       `json:"seconds_since_heartbeat,omitempty"`
	}

	var status struct {
		Status              string            `json:"status"`
		TreeSize            int64             `json:"tree_size"`
		TreeHash            string            `json:"tree_hash"`
		LastWitnessedSize   int64             `json:"last_witnessed_size"`
		UnconfirmedCount    int64             `json:"unconfirmed_count"`
		ActiveWitnesses     int               `json:"active_witnesses"`
		Witnesses           []*WitnessStatus  `json:"witnesses"`
		WitnessedTreeSizes  map[string]int    `json:"witnessed_tree_sizes"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Display status
	fmt.Println("\n📊 Lottery Transparency Log Status")
	fmt.Println("═══════════════════════════════════")
	
	statusIcon := "✅"
	statusText := status.Status
	if status.Status == "pending_witnesses" {
		statusIcon = "⏳"
		statusText = "Pending Witnesses"
	} else if status.Status == "empty" {
		statusIcon = "📭"
		statusText = "Empty"
	} else if status.Status == "healthy" {
		statusText = "Healthy"
	}

	fmt.Printf("%s Status: %s\n\n", statusIcon, statusText)
	
	fmt.Printf("🌲 Tree Information:\n")
	fmt.Printf("   Total Draws: %d\n", status.TreeSize)
	fmt.Printf("   Tree Hash: %s\n", status.TreeHash[:16]+"...")
	
	fmt.Printf("\n👁️  Witness Information:\n")
	fmt.Printf("   Active Witnesses: %d\n", status.ActiveWitnesses)
	fmt.Printf("   Last Witnessed Size: %d\n", status.LastWitnessedSize)
	
	if len(status.Witnesses) > 0 {
		fmt.Printf("\n   Witness Details:\n")
		for _, w := range status.Witnesses {
			timeAgo := time.Since(w.LastSignatureAt)
			timeStr := ""
			if timeAgo < time.Minute {
				timeStr = fmt.Sprintf("%d seconds ago", int(timeAgo.Seconds()))
			} else if timeAgo < time.Hour {
				timeStr = fmt.Sprintf("%d minutes ago", int(timeAgo.Minutes()))
			} else if timeAgo < 24*time.Hour {
				timeStr = fmt.Sprintf("%d hours ago", int(timeAgo.Hours()))
			} else {
				timeStr = fmt.Sprintf("%d days ago", int(timeAgo.Hours()/24))
			}
			onlineStatus := "🔴 Offline"
			if w.Online {
				onlineStatus = "🟢 Online"
			}
			fmt.Printf("   • %s: Tree size %d (%s) - %s\n", w.WitnessID, w.LastTreeSize, timeStr, onlineStatus)
		}
	}
	
	if status.UnconfirmedCount > 0 {
		fmt.Printf("\n⚠️  Unconfirmed Draws: %d\n", status.UnconfirmedCount)
		fmt.Printf("   Draws %d-%d are waiting for witness verification\n", 
			status.LastWitnessedSize+1, status.TreeSize)
	} else if status.TreeSize > 0 {
		fmt.Printf("\n✅ All draws have been witnessed\n")
	}

	return nil
}

func checkLocalStatus() error {
	lotteryLog, err := tlog.NewLotteryLog(getDataDir(), logger)
	if err != nil {
		return fmt.Errorf("failed to create lottery log: %w", err)
	}

	treeSize, err := lotteryLog.GetTreeSize()
	if err != nil {
		return fmt.Errorf("failed to get tree size: %w", err)
	}

	treeHash, err := lotteryLog.GetTreeHash()
	if err != nil {
		return fmt.Errorf("failed to get tree hash: %w", err)
	}

	cosignatures, err := lotteryLog.GetLatestWitnessCosignatures()
	if err != nil {
		return fmt.Errorf("failed to get cosignatures: %w", err)
	}

	// Find highest witnessed size
	lastWitnessedSize := int64(0)
	for _, cosig := range cosignatures {
		if cosig.TreeSize > lastWitnessedSize {
			lastWitnessedSize = cosig.TreeSize
		}
	}

	unconfirmedCount := int64(0)
	if treeSize > lastWitnessedSize {
		unconfirmedCount = treeSize - lastWitnessedSize
	}

	// Display status
	fmt.Println("\n📊 Lottery Transparency Log Status")
	fmt.Println("═══════════════════════════════════")
	
	statusIcon := "✅"
	statusText := "Healthy"
	if unconfirmedCount > 0 {
		statusIcon = "⏳"
		statusText = "Pending Witnesses"
	} else if treeSize == 0 {
		statusIcon = "📭"
		statusText = "Empty"
	}

	fmt.Printf("%s Status: %s\n\n", statusIcon, statusText)
	
	fmt.Printf("🌲 Tree Information:\n")
	fmt.Printf("   Total Draws: %d\n", treeSize)
	fmt.Printf("   Tree Hash: %x\n", treeHash[:8])
	
	fmt.Printf("\n👁️  Witness Information:\n")
	fmt.Printf("   Active Witnesses: %d\n", len(cosignatures))
	fmt.Printf("   Last Witnessed Size: %d\n", lastWitnessedSize)
	
	if len(cosignatures) > 0 {
		fmt.Printf("\n   Witness Details:\n")
		for _, cosig := range cosignatures {
			timeAgo := time.Since(cosig.Timestamp)
			timeStr := ""
			if timeAgo < time.Minute {
				timeStr = fmt.Sprintf("%d seconds ago", int(timeAgo.Seconds()))
			} else if timeAgo < time.Hour {
				timeStr = fmt.Sprintf("%d minutes ago", int(timeAgo.Minutes()))
			} else if timeAgo < 24*time.Hour {
				timeStr = fmt.Sprintf("%d hours ago", int(timeAgo.Hours()))
			} else {
				timeStr = fmt.Sprintf("%d days ago", int(timeAgo.Hours()/24))
			}
			fmt.Printf("   • %s: Tree size %d (%s)\n", cosig.WitnessID, cosig.TreeSize, timeStr)
		}
	}
	
	if unconfirmedCount > 0 {
		fmt.Printf("\n⚠️  Unconfirmed Draws: %d\n", unconfirmedCount)
		fmt.Printf("   Draws %d-%d are waiting for witness verification\n", 
			lastWitnessedSize+1, treeSize)
	} else if treeSize > 0 {
		fmt.Printf("\n✅ All draws have been witnessed\n")
	}

	return nil
}
