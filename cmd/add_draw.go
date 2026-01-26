package cmd

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"lottery-tlog/tlog"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	seqNo      int
	ip         string
	severity   string
	code       int
	text       string
	remoteIP   string
	game       int
	draw       int
	subdraw    int
	valuesFile string
	jsonFile   string
)

var addDrawCmd = &cobra.Command{
	Use:   "add-draw",
	Short: "Add a new lottery draw to the log",
	Long: `Add a new lottery event to the transparency log.
	
You can provide the event details via command-line flags or load from a JSON file.
For random value generation (code 300), use --values-file with a list of integers.`,
	SilenceUsage: true,
	RunE:         runAddDraw,
}

func init() {
	rootCmd.AddCommand(addDrawCmd)

	addDrawCmd.Flags().IntVar(&seqNo, "seqno", 0, "Sequence number (required)")
	addDrawCmd.Flags().StringVar(&ip, "ip", "", "Source IP address (required)")
	addDrawCmd.Flags().StringVar(&severity, "severity", "info", "Event severity")
	addDrawCmd.Flags().IntVar(&code, "code", 0, "Message code (required)")
	addDrawCmd.Flags().StringVar(&text, "text", "", "Message text (required)")
	addDrawCmd.Flags().StringVar(&remoteIP, "remote-ip", "", "Remote IP address (for codes requiring it)")
	addDrawCmd.Flags().IntVar(&game, "game", 0, "Game number (for codes requiring game properties)")
	addDrawCmd.Flags().IntVar(&draw, "draw", 0, "Draw number (for codes requiring game properties)")
	addDrawCmd.Flags().IntVar(&subdraw, "subdraw", 0, "Subdraw number (for codes requiring game properties)")
	addDrawCmd.Flags().StringVar(&valuesFile, "values-file", "", "JSON file with values array")
	addDrawCmd.Flags().StringVar(&jsonFile, "json-file", "", "Load complete draw from JSON file")
}

func runAddDraw(cmd *cobra.Command, args []string) error {
	lotteryLog, cleanup, err := createLotteryLog()
	if err != nil {
		return fmt.Errorf("failed to create lottery log: %w", err)
	}
	defer cleanup()

	var drawEvent tlog.LotteryDraw

	// Load from JSON file if provided
	if jsonFile != "" {
		data, err := os.ReadFile(jsonFile)
		if err != nil {
			return fmt.Errorf("failed to read JSON file: %w", err)
		}
		if err := json.Unmarshal(data, &drawEvent); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		// Build from command-line flags
		if ip == "" || text == "" {
			return fmt.Errorf("--ip and --text are required (or use --json-file)")
		}

		message := tlog.Message{
			Code:     code,
			Text:     text,
			RemoteIP: remoteIP,
		}

		// Add game properties if any are specified
		if game > 0 || draw > 0 || subdraw > 0 {
			message.GameProperties = &tlog.GameProperties{
				Game:    game,
				Draw:    draw,
				Subdraw: subdraw,
			}
		}

		// Load values from file if provided
		if valuesFile != "" {
			data, err := os.ReadFile(valuesFile)
			if err != nil {
				return fmt.Errorf("failed to read values file: %w", err)
			}
			var values []int
			if err := json.Unmarshal(data, &values); err != nil {
				return fmt.Errorf("failed to parse values: %w", err)
			}
			message.Values = values
		}

		// Generate MAC using HMAC-SHA256
		drawData, _ := json.Marshal(message)
		mac := generateMAC(drawData, fmt.Sprintf("%d-%s", seqNo, ip))

		drawEvent = tlog.LotteryDraw{
			Timestamp: time.Now(),
			SeqNo:     seqNo,
			IP:        ip,
			Severity:  severity,
			Message:   message,
			MAC:       mac,
		}
	}

	logger.Info("Adding draw event",
		"seqno", drawEvent.SeqNo,
		"code", drawEvent.Message.Code,
		"timestamp", drawEvent.Timestamp)

	if err := lotteryLog.AddDraw(drawEvent); err != nil {
		return fmt.Errorf("failed to add draw: %w", err)
	}

	size, _ := lotteryLog.GetTreeSize()
	hash, _ := lotteryLog.GetTreeHash(size)

	fmt.Println("✓ Draw event added successfully")
	fmt.Printf("  Seq No: %d\n", drawEvent.SeqNo)
	fmt.Printf("  Code: %d\n", drawEvent.Message.Code)
	fmt.Printf("  Text: %s\n", drawEvent.Message.Text)
	if drawEvent.Message.GameProperties != nil {
		fmt.Printf("  Game: %d, Draw: %d, Subdraw: %d\n",
			drawEvent.Message.GameProperties.Game,
			drawEvent.Message.GameProperties.Draw,
			drawEvent.Message.GameProperties.Subdraw)
	}
	fmt.Printf("  Index: %d\n", size-1)
	fmt.Printf("  Tree Size: %d\n", size)
	if len(hash) >= 8 {
		fmt.Printf("  Tree Hash: %x\n", hash[:8])
	}

	return nil
}

// generateMAC generates a message authentication code using HMAC-SHA256
func generateMAC(data []byte, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
