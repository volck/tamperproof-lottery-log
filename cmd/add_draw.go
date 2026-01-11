package cmd

import (
	"fmt"
	"lottery-tlog/tlog"
	"math/rand"
	"time"

	"github.com/spf13/cobra"
)

var (
	drawID      string
	position    int
	maxPosition int
	rngHash     string
	drawType    string
	randomDraw  bool
)

var addDrawCmd = &cobra.Command{
	Use:   "add-draw",
	Short: "Add a new lottery draw to the log",
	Long: `Add a new lottery draw to the transparency log.
	
You can either specify the draw details manually or use --random 
to generate a random draw for testing purposes.`,
	SilenceUsage: true,
	RunE:         runAddDraw,
}

func init() {
	rootCmd.AddCommand(addDrawCmd)

	addDrawCmd.Flags().StringVar(&drawID, "draw-id", "", "Unique draw identifier (required)")
	addDrawCmd.Flags().IntVar(&position, "position", 0, "Drawn position (1 to max-position)")
	addDrawCmd.Flags().IntVar(&maxPosition, "max-position", 100, "Maximum position (default 100)")
	addDrawCmd.Flags().StringVar(&rngHash, "rng-hash", "", "RNG hash used to generate position (hex string)")
	addDrawCmd.Flags().StringVar(&drawType, "type", "regular", "Draw type (regular, special, etc.)")
	addDrawCmd.Flags().BoolVar(&randomDraw, "random", false, "Generate random draw data")

	addDrawCmd.MarkFlagRequired("draw-id")
}

func runAddDraw(cmd *cobra.Command, args []string) error {
	lotteryLog, err := tlog.NewLotteryLog(getDataDir(), logger)
	if err != nil {
		return fmt.Errorf("failed to create lottery log: %w", err)
	}

	// Generate random draw if requested
	if randomDraw {
		// Generate RNG hash from timestamp
		seed := time.Now().UnixNano()
		rngHash = fmt.Sprintf("%016x", seed)
		
		rng := rand.New(rand.NewSource(seed))
		position = rng.Intn(maxPosition) + 1
		logger.Info("Generated random draw", "position", position, "max_position", maxPosition, "rng_hash", rngHash)
	} else if position == 0 {
		return fmt.Errorf("either provide --position or use --random flag")
	}

	if position < 1 || position > maxPosition {
		return fmt.Errorf("position must be between 1 and %d", maxPosition)
	}
	
	if rngHash == "" && randomDraw {
		return fmt.Errorf("rng hash should have been generated")
	}

	draw := tlog.LotteryDraw{
		DrawID:      drawID,
		Timestamp:   time.Now(),
		Position:    position,
		MaxPosition: maxPosition,
		RNGHash:     rngHash,
		DrawType:    drawType,
	}

	if err := lotteryLog.AddDraw(draw); err != nil {
		return fmt.Errorf("failed to add draw: %w", err)
	}

	size, _ := lotteryLog.GetTreeSize()
	treeHash, _ := lotteryLog.GetTreeHash()

	fmt.Printf("✓ Draw added successfully\n")
	fmt.Printf("  Draw ID: %s\n", draw.DrawID)
	fmt.Printf("  Position: %d of %d\n", draw.Position, draw.MaxPosition)
	if draw.RNGHash != "" {
		fmt.Printf("  RNG Hash: %s\n", draw.RNGHash)
	}
	fmt.Printf("  Index: %d\n", size-1)
	fmt.Printf("  Tree Size: %d\n", size)
	fmt.Printf("  Tree Hash: %x\n", treeHash[:8])

	return nil
}
