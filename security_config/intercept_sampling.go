package security_config

import (
	"sync"
)

type sampling struct {
	mu             sync.Mutex
	count          uint
	currentHarvest uint
	eventQuota     sync.Map
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

func (s *sampling) CalculateEventSampling(traceID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	count, ok := s.eventQuota.Load(traceID)

	if ok && count != nil {
		eventQuota := count.(int)
		if eventQuota > 100 {
			return false
		} else {
			s.eventQuota.Store(traceID, eventQuota+1)
			return true
		}
	} else {
		s.eventQuota.Store(traceID, 1)
		return true
	}
}
