package dualsteer

import (
	"errors"
	"fmt"
)

// Reasons a rule set is rejected as a whole. ErrRuleCountMismatch comes only
// from Decoder.RuleSet, which compares the header's rule count with the rules
// it reassembled.
var (
	ErrInvalidRuleSet      = errors.New("dualsteer: invalid rule set")
	ErrRuleCountMismatch   = fmt.Errorf("%w: rule count does not match header", ErrInvalidRuleSet)
	ErrNoCatchAll          = fmt.Errorf("%w: no DS catch-all", ErrInvalidRuleSet)
	ErrNoProbe             = fmt.Errorf("%w: no IPv4 Probe parameters", ErrInvalidRuleSet)
	ErrDuplicatePrecedence = fmt.Errorf("%w: duplicate precedence", ErrInvalidRuleSet)
	ErrTooManyRules        = fmt.Errorf("%w: too many rules", ErrInvalidRuleSet)
)

// Validate is the structural check of a DS rule set. The SMF runs it on its
// configuration and on the management API's input; the device runs it, through
// Decoder.RuleSet, before applying an FF01H. A rule set that fails is dropped
// as a whole. Every error wraps ErrInvalidRuleSet.
func (rs *RuleSet) Validate() error {
	if rs.Transmission != TransmissionSimultaneous && rs.Transmission != TransmissionNonSimultaneous {
		return fmt.Errorf("%w: transmission mode %d", ErrInvalidRuleSet, rs.Transmission)
	}
	if err := checkPositive(rs.Params); err != nil {
		return err
	}
	if rs.Probe == nil {
		return ErrNoProbe
	}
	if !rs.Probe.Responder.Is4() {
		return fmt.Errorf("%w: Probe responder %v is not IPv4", ErrInvalidRuleSet, rs.Probe.Responder)
	}

	ids := map[uint8]bool{}
	precedences := map[uint8]bool{}
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if err := r.validate(); err != nil {
			return fmt.Errorf("rule %d: %w", r.ID, err)
		}
		if ids[r.ID] {
			return fmt.Errorf("%w: duplicate rule ID %d", ErrInvalidRuleSet, r.ID)
		}
		if precedences[r.Precedence] {
			return fmt.Errorf("%w %d", ErrDuplicatePrecedence, r.Precedence)
		}
		ids[r.ID], precedences[r.Precedence] = true, true
	}
	if !ids[CatchAllRuleID] {
		return ErrNoCatchAll
	}
	if len(rs.Rules)-1 > MaxRules {
		return fmt.Errorf("%w: %d besides the DS catch-all, at most %d", ErrTooManyRules, len(rs.Rules)-1, MaxRules)
	}
	return nil
}

func (r *Rule) validate() error {
	if r.ID == CatchAllRuleID {
		if r.Precedence != CatchAllPrecedence || len(r.Filters) != 1 || r.Filters[0] != (PacketFilter{MatchAll: true}) {
			return fmt.Errorf("%w: the DS catch-all is precedence %d with one match-all filter",
				ErrInvalidRuleSet, CatchAllPrecedence)
		}
	} else {
		if r.ID == 0 || r.Precedence == CatchAllPrecedence {
			return fmt.Errorf("%w: rule ID must be 1-254 and precedence 0-254", ErrInvalidRuleSet)
		}
		if len(r.Filters) == 0 || len(r.Filters) > MaxPacketFilters {
			return fmt.Errorf("%w: %d packet filters, want 1-%d", ErrInvalidRuleSet, len(r.Filters), MaxPacketFilters)
		}
		for _, f := range r.Filters {
			if err := f.validate(); err != nil {
				return err
			}
		}
	}

	switch r.Mode {
	case SteeringActiveStandby:
		if !r.ActiveLeg.valid() {
			return fmt.Errorf("%w: Active-Standby needs an active Leg", ErrInvalidRuleSet)
		}
	case SteeringPriorityBased:
		if !r.Priority.PreferredLeg.valid() {
			return fmt.Errorf("%w: Priority-based needs a preferred Leg", ErrInvalidRuleSet)
		}
	case SteeringSmallestDelay:
	default:
		return fmt.Errorf("%w: Steering mode %d", ErrInvalidRuleSet, r.Mode)
	}

	// only the overrides that are set can fail
	return checkPositive(r.Overrides.Apply(DeviceParams{ProbeInterval: 1, K: 1, N: 1}))
}

func checkPositive(p DeviceParams) error {
	if p.ProbeInterval == 0 || p.K == 0 || p.N == 0 {
		return fmt.Errorf("%w: probe interval, K and N must be positive", ErrInvalidRuleSet)
	}
	return nil
}

func (f PacketFilter) validate() error {
	empty := !f.Remote.IsValid() && f.Protocol == nil && f.LocalPort == nil && f.RemotePort == nil
	switch {
	case f.MatchAll && !empty:
		return fmt.Errorf("%w: match-all packet filter with other components", ErrInvalidRuleSet)
	case !f.MatchAll && empty:
		return fmt.Errorf("%w: empty packet filter", ErrInvalidRuleSet)
	case f.Remote.IsValid() && !f.Remote.Addr().Is4():
		return fmt.Errorf("%w: remote address %v is not IPv4", ErrInvalidRuleSet, f.Remote)
	case f.LocalPort != nil && f.LocalPort.Low > f.LocalPort.High,
		f.RemotePort != nil && f.RemotePort.Low > f.RemotePort.High:
		return fmt.Errorf("%w: port range low above high", ErrInvalidRuleSet)
	}
	return nil
}
