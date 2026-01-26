package tlog

// StorageBackend defines the interface for different storage implementations
type StorageBackend interface {
	// AddDraw adds a new lottery draw
	AddDraw(draw LotteryDraw) error

	// GetDraw retrieves a draw by index
	GetDraw(index int64) (*LotteryDraw, error)

	// GetTreeSize returns the current tree size
	GetTreeSize() (int64, error)

	// GetTreeHash returns the tree hash for a given size
	GetTreeHash(size int64) (string, error)

	// ListDraws returns draws in a range
	ListDraws(startIndex, endIndex int64) ([]*LotteryDraw, error)

	// AddWitnessCosignature adds a witness signature
	AddWitnessCosignature(cosig WitnessCosignature) error

	// GetLatestWitnessCosignatures returns witness sigs for current tree
	GetLatestWitnessCosignatures() ([]WitnessCosignature, error)

	// VerifyIntegrity verifies the integrity of the log
	VerifyIntegrity() error
}

// LotteryLogAdapter provides a unified interface for both file and Oracle backends
type LotteryLogAdapter struct {
	backend StorageBackend
}

// NewLotteryLogAdapter creates a new adapter for the lottery log
func NewLotteryLogAdapter(backend StorageBackend) *LotteryLogAdapter {
	return &LotteryLogAdapter{
		backend: backend,
	}
}

// AddDraw adds a new lottery draw
func (a *LotteryLogAdapter) AddDraw(draw LotteryDraw) error {
	return a.backend.AddDraw(draw)
}

// GetDraw retrieves a draw by index
func (a *LotteryLogAdapter) GetDraw(index int64) (*LotteryDraw, error) {
	return a.backend.GetDraw(index)
}

// GetTreeSize returns the current tree size
func (a *LotteryLogAdapter) GetTreeSize() (int64, error) {
	return a.backend.GetTreeSize()
}

// GetTreeHash returns the tree hash for a given size
func (a *LotteryLogAdapter) GetTreeHash(size int64) (string, error) {
	return a.backend.GetTreeHash(size)
}

// ListDraws returns draws in a range
func (a *LotteryLogAdapter) ListDraws(startIndex, endIndex int64) ([]*LotteryDraw, error) {
	return a.backend.ListDraws(startIndex, endIndex)
}

// AddWitnessCosignature adds a witness signature
func (a *LotteryLogAdapter) AddWitnessCosignature(cosig WitnessCosignature) error {
	return a.backend.AddWitnessCosignature(cosig)
}

// GetLatestWitnessCosignatures returns witness sigs for current tree
func (a *LotteryLogAdapter) GetLatestWitnessCosignatures() ([]WitnessCosignature, error) {
	return a.backend.GetLatestWitnessCosignatures()
}

// VerifyIntegrity verifies the integrity of the log
func (a *LotteryLogAdapter) VerifyIntegrity() error {
	return a.backend.VerifyIntegrity()
}
