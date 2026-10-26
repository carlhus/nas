package dualsteer

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/free5gc/nas/ie"
)

// Reasons a container is ignored, reported through Decoder.Ignored.
var (
	ErrPLMNMismatch         = errors.New("dualsteer: container PLMN does not match")
	ErrUnknownFormatVersion = errors.New("dualsteer: unknown container format version")
)

// ErrMalformed marks bytes that cannot be decoded.
var ErrMalformed = errors.New("dualsteer: malformed")

// Encoder writes DS containers for one PLMN.
type Encoder struct {
	PLMN PLMN
}

// Decoder reads DS containers addressed to one PLMN.
type Decoder struct {
	PLMN PLMN
	// Ignored, if set, is told about each container that is skipped as a
	// whole: PLMN mismatch, unknown format version, or too short to tell.
	Ignored func(id uint16, err error)
}

type record struct {
	typ   uint8
	value []byte
}

func (e Encoder) container(id uint16, records []byte) ie.OperatorContainer {
	b := make([]byte, 0, containerPrefixLen+len(records))
	b = append(b, e.PLMN[:]...)
	b = append(b, FormatVersion)
	b = append(b, records...)
	return ie.OperatorContainer{ID: id, Contents: b}
}

func appendRecord(b []byte, typ uint8, value []byte) []byte {
	b = append(b, typ, uint8(len(value)))
	return append(b, value...)
}

// parseTLVs splits b into TLVs. It fails on a TLV that overruns b.
func parseTLVs(b []byte) ([]record, error) {
	var recs []record
	for len(b) > 0 {
		if len(b) < 2 || len(b) < 2+int(b[1]) {
			return nil, fmt.Errorf("%w: truncated TLV", ErrMalformed)
		}
		recs = append(recs, record{typ: b[0], value: b[2 : 2+int(b[1])]})
		b = b[2+int(b[1]):]
	}
	return recs, nil
}

// records returns, in order, the TLV records of each container with the given
// ID that is addressed to d.PLMN in a known format.
func (d *Decoder) records(cs []ie.OperatorContainer, id uint16) ([][]record, error) {
	var out [][]record
	for _, c := range cs {
		if c.ID != id {
			continue
		}
		var reason error
		switch {
		case len(c.Contents) < containerPrefixLen:
			reason = fmt.Errorf("%w: container shorter than PLMN and format version", ErrMalformed)
		case PLMN(c.Contents[:3]) != d.PLMN:
			reason = fmt.Errorf("%w: got %x", ErrPLMNMismatch, c.Contents[:3])
		case c.Contents[3] != FormatVersion:
			reason = fmt.Errorf("%w: %d", ErrUnknownFormatVersion, c.Contents[3])
		}
		if reason != nil {
			if d.Ignored != nil {
				d.Ignored(c.ID, reason)
			}
			continue
		}
		recs, err := parseTLVs(c.Contents[containerPrefixLen:])
		if err != nil {
			return nil, fmt.Errorf("container %#04x: %w", id, err)
		}
		out = append(out, recs)
	}
	return out, nil
}

// Capability returns FF00H, the device's DS capability.
func (e Encoder) Capability() ie.OperatorContainer {
	return e.container(ContainerCapability, nil)
}

// Capability reports whether cs holds an FF00H for d.PLMN.
func (d *Decoder) Capability(cs []ie.OperatorContainer) bool {
	recs, err := d.records(cs, ContainerCapability)
	return err == nil && len(recs) > 0
}

// single returns the records of the one container with the given ID; found
// is false if there is none.
func (d *Decoder) single(cs []ie.OperatorContainer, id uint16) (recs []record, found bool, err error) {
	all, err := d.records(cs, id)
	switch {
	case err != nil:
		return nil, false, err
	case len(all) > 1:
		return nil, false, fmt.Errorf("%w: %d containers %#04x, want one", ErrMalformed, len(all), id)
	case len(all) == 0:
		return nil, false, nil
	}
	return all[0], true, nil
}

// atLeast checks that a record value has at least n bytes. Later fields may be
// appended to a record without a new format version, so extra bytes are fine.
func atLeast(r record, n int) error {
	if len(r.value) < n {
		return fmt.Errorf("%w: record %#02x has %d bytes, want %d", ErrMalformed, r.typ, len(r.value), n)
	}
	return nil
}

// DLState returns FF03H.
func (e Encoder) DLState(s DLState) (ie.OperatorContainer, error) {
	if len(s.Legs) > maxRuleLegs {
		return ie.OperatorContainer{}, fmt.Errorf("dualsteer: DL state has %d rules, at most %d", len(s.Legs), maxRuleLegs)
	}
	entries := make([]byte, 0, 2*len(s.Legs))
	for _, l := range s.Legs {
		entries = append(entries, l.RuleID, uint8(l.Leg))
	}
	b := appendRecord(nil, recDLStateHeader, []byte{s.Version, uint8(s.Result)})
	b = appendRecord(b, recDLStateEntries, entries)
	return e.container(ContainerDLState, b), nil
}

// DLState decodes the FF03H in cs; it returns nil if there is none.
func (d *Decoder) DLState(cs []ie.OperatorContainer) (*DLState, error) {
	recs, found, err := d.single(cs, ContainerDLState)
	if err != nil || !found {
		return nil, err
	}
	var s DLState
	var header bool
	for _, r := range recs {
		switch r.typ {
		case recDLStateHeader:
			if err := atLeast(r, 2); err != nil {
				return nil, err
			}
			s.Version, s.Result, header = r.value[0], Result(r.value[1]), true
		case recDLStateEntries:
			if len(r.value)%2 != 0 {
				return nil, fmt.Errorf("%w: DL state entries of odd length %d", ErrMalformed, len(r.value))
			}
			for i := 0; i < len(r.value); i += 2 {
				s.Legs = append(s.Legs, RuleLeg{RuleID: r.value[i], Leg: Access(r.value[i+1])})
			}
		}
	}
	if !header {
		return nil, fmt.Errorf("%w: FF03H without header", ErrMalformed)
	}
	return &s, nil
}

func appendMeasurement(b []byte, a Access, m Measurement) []byte {
	v := []byte{uint8(a)}
	v = binary.BigEndian.AppendUint16(v, m.RTT)
	v = binary.BigEndian.AppendUint16(v, m.Loss)
	v = append(v, m.ConsecutiveTimeouts)
	return appendRecord(b, recMeasurement, v)
}

// SwitchRequest returns FF02H.
func (e Encoder) SwitchRequest(r SwitchRequest) (ie.OperatorContainer, error) {
	if len(r.RuleIDs) == 0 || len(r.RuleIDs) > maxRuleLegs {
		return ie.OperatorContainer{}, fmt.Errorf("dualsteer: switch request names %d rules, want 1-%d",
			len(r.RuleIDs), maxRuleLegs)
	}
	b := appendRecord(nil, recSwitchHeader, []byte{r.Version, uint8(r.Trigger)})
	b = appendRecord(b, recSwitchRuleIDs, r.RuleIDs)
	b = appendMeasurement(b, AccessTN, r.TN)
	b = appendMeasurement(b, AccessNTN, r.NTN)
	return e.container(ContainerSwitchRequest, b), nil
}

// SwitchRequest decodes the FF02H in cs; it returns nil if there is none.
func (d *Decoder) SwitchRequest(cs []ie.OperatorContainer) (*SwitchRequest, error) {
	recs, found, err := d.single(cs, ContainerSwitchRequest)
	if err != nil || !found {
		return nil, err
	}
	var r SwitchRequest
	var header, tn, ntn bool
	for _, rec := range recs {
		switch rec.typ {
		case recSwitchHeader:
			if err := atLeast(rec, 2); err != nil {
				return nil, err
			}
			r.Version, r.Trigger, header = rec.value[0], Trigger(rec.value[1]), true
		case recSwitchRuleIDs:
			r.RuleIDs = append(r.RuleIDs, rec.value...)
		case recMeasurement:
			if err := atLeast(rec, 6); err != nil {
				return nil, err
			}
			m := Measurement{
				RTT:                 binary.BigEndian.Uint16(rec.value[1:]),
				Loss:                binary.BigEndian.Uint16(rec.value[3:]),
				ConsecutiveTimeouts: rec.value[5],
			}
			switch Access(rec.value[0]) {
			case AccessTN:
				r.TN, tn = m, true
			case AccessNTN:
				r.NTN, ntn = m, true
			default:
				return nil, fmt.Errorf("%w: measurement for unknown access %d", ErrMalformed, rec.value[0])
			}
		}
	}
	if !header || !tn || !ntn || len(r.RuleIDs) == 0 {
		return nil, fmt.Errorf("%w: FF02H needs a header, rule IDs and both measurements", ErrMalformed)
	}
	return &r, nil
}
