package dualsteer

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/free5gc/nas/ie"
)

// RuleSet returns the FF01H containers for rs, in order. Records are packed
// greedily; the header record opens the first container. rs must pass
// Validate.
func (e Encoder) RuleSet(rs RuleSet) ([]ie.OperatorContainer, error) {
	if err := rs.Validate(); err != nil {
		return nil, err
	}
	header := []byte{rs.Version, uint8(len(rs.Rules)), uint8(rs.Transmission)}
	header = appendParams(header, rs.Params)
	recs := [][]byte{
		appendRecord(nil, recRuleSetHeader, header),
		appendRecord(nil, recProbeIPv4, encodeProbe(rs.Probe)),
	}
	for _, r := range rs.Rules {
		rec := appendRecord(nil, recRule, encodeRule(r))
		if len(rec) > MaxRecordsLen {
			return nil, fmt.Errorf("%w: rule %d takes %d bytes, more than one container", ErrInvalidRuleSet,
				r.ID, len(rec))
		}
		recs = append(recs, rec)
	}

	var cs []ie.OperatorContainer
	var cur []byte
	for _, rec := range recs {
		if len(cur)+len(rec) > MaxRecordsLen {
			cs = append(cs, e.container(ContainerRuleSet, cur))
			cur = nil
		}
		cur = append(cur, rec...)
	}
	return append(cs, e.container(ContainerRuleSet, cur)), nil
}

// RuleSet reassembles the FF01H containers in cs, in order, and checks the
// result with Validate. It returns nil if there is none. Any error means the
// whole rule set is to be dropped and the old one kept.
func (d *Decoder) RuleSet(cs []ie.OperatorContainer) (*RuleSet, error) {
	all, err := d.records(cs, ContainerRuleSet)
	if err != nil || len(all) == 0 {
		return nil, err
	}
	if len(all[0]) == 0 || all[0][0].typ != recRuleSetHeader {
		return nil, fmt.Errorf("%w: FF01H does not open with the header record", ErrMalformed)
	}

	var rs RuleSet
	var count uint8
	for i, recs := range all {
		for j, rec := range recs {
			switch rec.typ {
			case recRuleSetHeader:
				if i != 0 || j != 0 {
					return nil, fmt.Errorf("%w: FF01H header record not first", ErrMalformed)
				}
				if err := atLeast(rec, 3); err != nil {
					return nil, err
				}
				rs.Version, count, rs.Transmission = rec.value[0], rec.value[1], TransmissionMode(rec.value[2])
				rs.Params = DefaultDeviceParams()
				var o DeviceParamOverrides
				if err := forEachTLV(rec.value[3:], func(typ uint8, v []byte) error {
					return decodeParam(&o, typ, v)
				}); err != nil {
					return nil, err
				}
				rs.Params = o.Apply(rs.Params)
			case recProbeIPv4:
				if err := atLeast(rec, 10); err != nil {
					return nil, err
				}
				rs.Probe = decodeProbe(rec.value)
			case recRule:
				r, err := decodeRule(rec.value)
				if err != nil {
					return nil, err
				}
				rs.Rules = append(rs.Rules, r)
			}
		}
	}
	if len(rs.Rules) != int(count) {
		return nil, fmt.Errorf("%w: header says %d rules, got %d", ErrRuleCountMismatch, count, len(rs.Rules))
	}
	if err := rs.Validate(); err != nil {
		return nil, err
	}
	return &rs, nil
}

func forEachTLV(b []byte, f func(typ uint8, v []byte) error) error {
	tlvs, err := parseTLVs(b)
	if err != nil {
		return err
	}
	for _, t := range tlvs {
		if err := f(t.typ, t.value); err != nil {
			return err
		}
	}
	return nil
}

func encodeProbe(p *Probe) []byte {
	a := p.Responder.As4()
	b := a[:]
	b = binary.BigEndian.AppendUint16(b, p.ResponderPort)
	b = binary.BigEndian.AppendUint16(b, p.TNPort)
	return binary.BigEndian.AppendUint16(b, p.NTNPort)
}

func decodeProbe(v []byte) *Probe {
	return &Probe{
		Responder:     netip.AddrFrom4([4]byte(v[:4])),
		ResponderPort: binary.BigEndian.Uint16(v[4:]),
		TNPort:        binary.BigEndian.Uint16(v[6:]),
		NTNPort:       binary.BigEndian.Uint16(v[8:]),
	}
}

func appendParam16(b []byte, typ uint8, v uint16) []byte {
	return appendRecord(b, typ, binary.BigEndian.AppendUint16(nil, v))
}

func appendParams(b []byte, p DeviceParams) []byte {
	return appendOverrides(b, DeviceParamOverrides{
		ProbeInterval: &p.ProbeInterval, K: &p.K, TimeoutFloor: &p.TimeoutFloor, TRestore: &p.TRestore,
		MinDwell: &p.MinDwell, HoldDown: &p.HoldDown, Delta: &p.Delta, N: &p.N,
	})
}

func appendOverrides(b []byte, o DeviceParamOverrides) []byte {
	if o.ProbeInterval != nil {
		b = appendParam16(b, paramProbeInterval, *o.ProbeInterval)
	}
	if o.K != nil {
		b = appendRecord(b, paramK, []byte{*o.K})
	}
	if o.TimeoutFloor != nil {
		b = appendParam16(b, paramTimeoutFloor, *o.TimeoutFloor)
	}
	if o.TRestore != nil {
		b = appendParam16(b, paramTRestore, *o.TRestore)
	}
	if o.MinDwell != nil {
		b = appendParam16(b, paramMinDwell, *o.MinDwell)
	}
	if o.HoldDown != nil {
		b = appendParam16(b, paramHoldDown, *o.HoldDown)
	}
	if o.Delta != nil {
		b = appendParam16(b, paramDelta, *o.Delta)
	}
	if o.N != nil {
		b = appendRecord(b, paramN, []byte{*o.N})
	}
	return b
}

// decodeParam sets the parameter typ in o. Types outside the parameter range
// are left alone; the caller handles or skips them.
func decodeParam(o *DeviceParamOverrides, typ uint8, v []byte) error {
	u8 := func(dst **uint8) error {
		if len(v) != 1 {
			return fmt.Errorf("%w: parameter %#02x has %d bytes, want 1", ErrMalformed, typ, len(v))
		}
		*dst = new(v[0])
		return nil
	}
	u16 := func(dst **uint16) error {
		if len(v) != 2 {
			return fmt.Errorf("%w: parameter %#02x has %d bytes, want 2", ErrMalformed, typ, len(v))
		}
		*dst = new(binary.BigEndian.Uint16(v))
		return nil
	}
	switch typ {
	case paramProbeInterval:
		return u16(&o.ProbeInterval)
	case paramK:
		return u8(&o.K)
	case paramTimeoutFloor:
		return u16(&o.TimeoutFloor)
	case paramTRestore:
		return u16(&o.TRestore)
	case paramMinDwell:
		return u16(&o.MinDwell)
	case paramHoldDown:
		return u16(&o.HoldDown)
	case paramDelta:
		return u16(&o.Delta)
	case paramN:
		return u8(&o.N)
	}
	return nil
}

func encodeRule(r Rule) []byte {
	b := []byte{r.ID, r.Precedence, uint8(r.Mode)}
	for _, f := range r.Filters {
		b = appendRecord(b, subPacketFilter, encodeFilter(f))
	}
	switch r.Mode {
	case SteeringActiveStandby:
		b = appendRecord(b, subActiveLeg, []byte{uint8(r.ActiveLeg)})
	case SteeringPriorityBased:
		p := r.Priority
		v := []byte{uint8(p.PreferredLeg)}
		for _, x := range []uint16{p.MaxRTT, p.MaxLoss, p.RTTMargin, p.LossMargin} {
			v = binary.BigEndian.AppendUint16(v, x)
		}
		b = appendRecord(b, subPriority, v)
	}
	return appendOverrides(b, r.Overrides)
}

func decodeRule(v []byte) (Rule, error) {
	if len(v) < 3 {
		return Rule{}, fmt.Errorf("%w: rule record has %d bytes", ErrMalformed, len(v))
	}
	r := Rule{ID: v[0], Precedence: v[1], Mode: SteeringMode(v[2])}
	err := forEachTLV(v[3:], func(typ uint8, v []byte) error {
		switch typ {
		case subPacketFilter:
			f, err := decodeFilter(v)
			if err != nil {
				return err
			}
			r.Filters = append(r.Filters, f)
		case subActiveLeg:
			if len(v) < 1 {
				return fmt.Errorf("%w: empty active Leg", ErrMalformed)
			}
			r.ActiveLeg = Access(v[0])
		case subPriority:
			if len(v) < 9 {
				return fmt.Errorf("%w: Priority-based parameters have %d bytes", ErrMalformed, len(v))
			}
			r.Priority = PriorityParams{
				PreferredLeg: Access(v[0]),
				MaxRTT:       binary.BigEndian.Uint16(v[1:]),
				MaxLoss:      binary.BigEndian.Uint16(v[3:]),
				RTTMargin:    binary.BigEndian.Uint16(v[5:]),
				LossMargin:   binary.BigEndian.Uint16(v[7:]),
			}
		default:
			return decodeParam(&r.Overrides, typ, v)
		}
		return nil
	})
	if err != nil {
		return Rule{}, fmt.Errorf("rule %d: %w", r.ID, err)
	}
	return r, nil
}

func appendPortComponent(b []byte, single, rng uint8, p *PortRange) []byte {
	if p.Low == p.High {
		return binary.BigEndian.AppendUint16(append(b, single), p.Low)
	}
	b = binary.BigEndian.AppendUint16(append(b, rng), p.Low)
	return binary.BigEndian.AppendUint16(b, p.High)
}

// encodeFilter writes TS 24.501 packet filter contents.
func encodeFilter(f PacketFilter) []byte {
	var b []byte
	if f.MatchAll {
		b = append(b, compMatchAll)
	}
	if f.Remote.IsValid() {
		addr := f.Remote.Addr().As4()
		mask := binary.BigEndian.AppendUint32(nil, ^uint32(0)<<(32-f.Remote.Bits()))
		b = append(append(append(b, compIPv4Remote), addr[:]...), mask...)
	}
	if f.Protocol != nil {
		b = append(b, compProtocol, *f.Protocol)
	}
	if f.LocalPort != nil {
		b = appendPortComponent(b, compLocalPort, compLocalPortRange, f.LocalPort)
	}
	if f.RemotePort != nil {
		b = appendPortComponent(b, compRemotePort, compRemotePortRange, f.RemotePort)
	}
	return b
}

func decodeFilter(b []byte) (PacketFilter, error) {
	var f PacketFilter
	seen := map[uint8]bool{}
	need := func(n int) error {
		if len(b) < 1+n {
			return fmt.Errorf("%w: packet filter component %#02x truncated", ErrMalformed, b[0])
		}
		return nil
	}
	for len(b) > 0 {
		typ := b[0]
		// a single port and a port range count as the same component
		kind := typ &^ 0x01
		if seen[kind] {
			return f, fmt.Errorf("%w: packet filter repeats component %#02x", ErrMalformed, typ)
		}
		seen[kind] = true
		var n int
		switch typ {
		case compMatchAll:
			f.MatchAll = true
		case compIPv4Remote:
			n = 8
			if err := need(n); err != nil {
				return f, err
			}
			mask := binary.BigEndian.Uint32(b[5:])
			bits := 0
			for mask&(1<<31) != 0 {
				mask <<= 1
				bits++
			}
			if mask != 0 {
				return f, fmt.Errorf("%w: non-contiguous IPv4 mask %x", ErrMalformed, b[5:9])
			}
			f.Remote = netip.PrefixFrom(netip.AddrFrom4([4]byte(b[1:5])), bits)
		case compProtocol:
			n = 1
			if err := need(n); err != nil {
				return f, err
			}
			f.Protocol = new(b[1])
		case compLocalPort, compRemotePort:
			n = 2
			if err := need(n); err != nil {
				return f, err
			}
			p := binary.BigEndian.Uint16(b[1:])
			setPort(&f, typ == compLocalPort, PortRange{Low: p, High: p})
		case compLocalPortRange, compRemotePortRange:
			n = 4
			if err := need(n); err != nil {
				return f, err
			}
			setPort(&f, typ == compLocalPortRange,
				PortRange{Low: binary.BigEndian.Uint16(b[1:]), High: binary.BigEndian.Uint16(b[3:])})
		default:
			return f, fmt.Errorf("%w: packet filter component %#02x not allowed in a DS rule", ErrMalformed, typ)
		}
		b = b[1+n:]
	}
	return f, nil
}

func setPort(f *PacketFilter, local bool, p PortRange) {
	if local {
		f.LocalPort = &p
	} else {
		f.RemotePort = &p
	}
}
