package security_config

import (
	"sync"

	logging "github.com/newrelic/csec-go-agent/internal/security_logs"
)

var logger = logging.GetLogger("lll")

type sampling struct {
	mu              sync.Mutex
	count           uint
	currentHarvest  uint
	previousHarvest uint
}

func (s *sampling) CalculateSampling() (bool, uint, uint, uint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentHarvest > 0 {
		s.currentHarvest--
		return false, s.currentHarvest, s.previousHarvest, 0
	}
	if s.previousHarvest > 0 {
		s.previousHarvest--
		return false, s.currentHarvest, s.previousHarvest, 1
	}
	return false, s.currentHarvest, s.previousHarvest, 2
}

func (s *sampling) Reset() {

	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	if s.count >= 12 {
		s.currentHarvest = 8
		s.previousHarvest = 0
		s.count = 0
	} else {
		s.previousHarvest += s.currentHarvest
		s.currentHarvest = 8
	}
	if s.previousHarvest >= 10 {
		s.previousHarvest = 10
	}
	logger.Info("RESET", s.currentHarvest, s.previousHarvest)
}
func main() {

	// a := sampling{
	// 	currentHarvest:  8,
	// 	previousHarvest: 1,
	// }

}
