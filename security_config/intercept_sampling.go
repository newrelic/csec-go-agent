package security_config

import (
	"sync"
)

type sampling struct {
	mu             sync.Mutex
	count          uint
	currentHarvest uint
}

func (s *sampling) CalculateSampling() (bool, uint) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentHarvest > 0 {
		s.currentHarvest--
		return true, s.currentHarvest
	}
	return false, s.currentHarvest
}

func (s *sampling) Reset() {

	s.mu.Lock()
	defer s.mu.Unlock()
	s.count = 0
}
