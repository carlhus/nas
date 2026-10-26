package dualsteer

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/nas/ie"
)

var testProbe = &Probe{
	Responder:     netip.MustParseAddr("10.60.0.1"),
	ResponderPort: 9999,
	TNPort:        40001,
	NTNPort:       40002,
}

func catchAll(mode SteeringMode) Rule {
	return Rule{
		ID:         CatchAllRuleID,
		Precedence: CatchAllPrecedence,
		Filters:    []PacketFilter{{MatchAll: true}},
		Mode:       mode,
	}
}

func TestRuleSetRoundTrip(t *testing.T) {
	t.Parallel()

	rs := RuleSet{
		Version:      5,
		Transmission: TransmissionSimultaneous,
		Params:       DefaultDeviceParams(),
		Probe:        testProbe,
		Rules: []Rule{
			{
				ID:         1,
				Precedence: 10,
				Filters: []PacketFilter{{
					Remote:     netip.MustParsePrefix("10.0.0.0/8"),
					Protocol:   new(uint8(17)),
					RemotePort: &PortRange{Low: 5000, High: 5000},
				}},
				Mode:      SteeringActiveStandby,
				ActiveLeg: AccessNTN,
				Overrides: DeviceParamOverrides{MinDwell: new(uint16(1000))},
			},
			catchAll(SteeringSmallestDelay),
		},
	}
	cs, err := Encoder{PLMN: testPLMN}.RuleSet(rs)
	require.NoError(t, err)
	require.Equal(t, []ie.OperatorContainer{{ID: 0xff01, Contents: []byte{
		0x02, 0xf8, 0x39, 0x01,
		0x01, 0x21, 0x05, 0x02, 0x01, // header: version 5, 2 rules, Simultaneous
		0x40, 0x02, 0x00, 0xc8, // probe interval 200 ms
		0x41, 0x01, 0x03, // K 3
		0x42, 0x02, 0x00, 0x64, // floor 100 ms
		0x43, 0x02, 0x0b, 0xb8, // T_restore 3 s
		0x44, 0x02, 0x0b, 0xb8, // minDwell 3 s
		0x45, 0x02, 0x13, 0x88, // hold-down 5 s
		0x46, 0x02, 0x00, 0x0f, // delta 15 ms
		0x47, 0x01, 0x03, // N 3
		0x02, 0x0a, 0x0a, 0x3c, 0x00, 0x01, 0x27, 0x0f, 0x9c, 0x41, 0x9c, 0x42, // probe
		0x03, 0x1a, 0x01, 0x0a, 0x01, // rule 1, precedence 10, AS
		0x01, 0x0e, // packet filter
		0x10, 0x0a, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, // remote 10.0.0.0/8
		0x30, 0x11, // UDP
		0x50, 0x13, 0x88, // remote port 5000
		0x02, 0x01, 0x02, // active Leg NTN
		0x44, 0x02, 0x03, 0xe8, // minDwell 1 s
		0x03, 0x06, 0xff, 0xff, 0x02, 0x01, 0x01, 0x01, // DS catch-all, SD, match-all
	}}}, cs)

	d, _ := recordingDecoder(testPLMN)
	got, err := d.RuleSet(cs)
	require.NoError(t, err)
	require.Equal(t, &rs, got)
}

func TestRuleSetHeaderOmitsParamsMeansDefaults(t *testing.T) {
	t.Parallel()

	c := ie.OperatorContainer{ID: 0xff01, Contents: []byte{
		0x02, 0xf8, 0x39, 0x01,
		0x01, 0x07, 0x05, 0x01, 0x02, // header: version 5, 1 rule, Non-simultaneous
		0x46, 0x02, 0x00, 0x14, // delta 20 ms
		0x02, 0x0a, 0x0a, 0x3c, 0x00, 0x01, 0x27, 0x0f, 0x9c, 0x41, 0x9c, 0x42,
		0x03, 0x06, 0xff, 0xff, 0x02, 0x01, 0x01, 0x01,
	}}
	d, _ := recordingDecoder(testPLMN)
	got, err := d.RuleSet([]ie.OperatorContainer{c})
	require.NoError(t, err)
	want := DefaultDeviceParams()
	want.Delta = 20
	require.Equal(t, want, got.Params)
	require.Equal(t, TransmissionNonSimultaneous, got.Transmission)
}

// fullRuleSet has MaxRules rules plus the DS catch-all, every rule carrying
// MaxPacketFilters IPv4 filters with every component and every override.
func fullRuleSet() RuleSet {
	rs := RuleSet{
		Version:      200,
		Transmission: TransmissionNonSimultaneous,
		Params:       DefaultDeviceParams(),
		Probe:        testProbe,
	}
	for i := range MaxRules {
		r := Rule{
			ID:         uint8(i + 1),
			Precedence: uint8(i),
			Mode:       SteeringPriorityBased,
			Priority: PriorityParams{
				PreferredLeg: AccessTN, MaxRTT: 150, MaxLoss: 20, RTTMargin: 10, LossMargin: 5,
			},
			Overrides: DeviceParamOverrides{
				ProbeInterval: new(uint16(100)), K: new(uint8(4)), TimeoutFloor: new(uint16(50)),
				TRestore: new(uint16(2000)), MinDwell: new(uint16(1000)), HoldDown: new(uint16(4000)),
				Delta: new(uint16(10)), N: new(uint8(5)),
			},
		}
		for j := range MaxPacketFilters {
			r.Filters = append(r.Filters, PacketFilter{
				Remote:     netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, uint8(j)}), 32),
				Protocol:   new(uint8(6)),
				LocalPort:  &PortRange{Low: 1000, High: 2000},
				RemotePort: &PortRange{Low: 3000, High: 4000},
			})
		}
		rs.Rules = append(rs.Rules, r)
	}
	rs.Rules = append(rs.Rules, catchAll(SteeringSmallestDelay))
	return rs
}

func TestRuleSetFragmentsAcrossContainers(t *testing.T) {
	t.Parallel()

	rs := fullRuleSet()
	cs, err := Encoder{PLMN: testPLMN}.RuleSet(rs)
	require.NoError(t, err)
	// A full rule fits in one container, so there is at most one per rule plus
	// the one that opens with the header.
	require.Greater(t, len(cs), 1)
	require.LessOrEqual(t, len(cs), len(rs.Rules)+1)
	for _, c := range cs {
		require.Equal(t, ContainerRuleSet, c.ID)
		require.LessOrEqual(t, len(c.Contents), MaxContainerContents)
	}

	d, _ := recordingDecoder(testPLMN)
	got, err := d.RuleSet(cs)
	require.NoError(t, err)
	require.Equal(t, &rs, got)

	// Records do not span containers: losing the last container leaves a rule
	// set that parses but is short of rules.
	_, err = d.RuleSet(cs[:len(cs)-1])
	require.ErrorIs(t, err, ErrRuleCountMismatch)
}

func TestRuleSetFragmentsMustStartWithHeader(t *testing.T) {
	t.Parallel()

	cs, err := Encoder{PLMN: testPLMN}.RuleSet(fullRuleSet())
	require.NoError(t, err)
	cs[0], cs[1] = cs[1], cs[0]

	d, _ := recordingDecoder(testPLMN)
	_, err = d.RuleSet(cs)
	require.ErrorIs(t, err, ErrMalformed)
}

func TestRuleSetSkipsUnknownRecordsAndSubTLVs(t *testing.T) {
	t.Parallel()

	c := ie.OperatorContainer{ID: 0xff01, Contents: []byte{
		0x02, 0xf8, 0x39, 0x01,
		0x01, 0x06, 0x05, 0x02, 0x01, 0x7f, 0x01, 0x00, // header with an unknown parameter
		0x02, 0x0a, 0x0a, 0x3c, 0x00, 0x01, 0x27, 0x0f, 0x9c, 0x41, 0x9c, 0x42,
		0x7f, 0x02, 0xaa, 0xbb, // unknown record
		0x03, 0x0a, 0x01, 0x0a, 0x02, 0x01, 0x02, 0x30, 0x11, 0x3f, 0x01, 0xcc, // rule 1 with an unknown sub-TLV
		0x03, 0x06, 0xff, 0xff, 0x02, 0x01, 0x01, 0x01,
	}}
	d, _ := recordingDecoder(testPLMN)
	got, err := d.RuleSet([]ie.OperatorContainer{c})
	require.NoError(t, err)
	require.Equal(t, &RuleSet{
		Version:      5,
		Transmission: TransmissionSimultaneous,
		Params:       DefaultDeviceParams(),
		Probe:        testProbe,
		Rules: []Rule{
			{ID: 1, Precedence: 10, Filters: []PacketFilter{{Protocol: new(uint8(17))}}, Mode: SteeringSmallestDelay},
			catchAll(SteeringSmallestDelay),
		},
	}, got)
}

func TestRuleSetRejectsDisallowedFilterComponent(t *testing.T) {
	t.Parallel()

	c := ie.OperatorContainer{ID: 0xff01, Contents: []byte{
		0x02, 0xf8, 0x39, 0x01,
		0x01, 0x03, 0x05, 0x02, 0x01,
		0x02, 0x0a, 0x0a, 0x3c, 0x00, 0x01, 0x27, 0x0f, 0x9c, 0x41, 0x9c, 0x42,
		0x03, 0x08, 0x01, 0x0a, 0x02, 0x01, 0x03, 0x60, 0x00, 0x01, // security parameter index
		0x03, 0x06, 0xff, 0xff, 0x02, 0x01, 0x01, 0x01,
	}}
	d, _ := recordingDecoder(testPLMN)
	_, err := d.RuleSet([]ie.OperatorContainer{c})
	require.ErrorIs(t, err, ErrMalformed)
}

func TestRuleSetThroughEPCO(t *testing.T) {
	t.Parallel()

	rs := fullRuleSet()
	e := Encoder{PLMN: testPLMN}
	cs, err := e.RuleSet(rs)
	require.NoError(t, err)
	dl, err := e.DLState(DLState{Version: rs.Version, Legs: []RuleLeg{{RuleID: CatchAllRuleID, Leg: AccessTN}}})
	require.NoError(t, err)

	b, err := (&ie.ExtendedProtCfgOpts{FromNw: &ie.ExtCfgOptFromNw{OperatorContainers: append(cs, dl)}}).MarshalBinary()
	require.NoError(t, err)
	opts := new(ie.ExtendedProtCfgOpts)
	require.NoError(t, opts.UnmarshalFromNw(b))

	d, _ := recordingDecoder(testPLMN)
	got, err := d.RuleSet(opts.FromNw.OperatorContainers)
	require.NoError(t, err)
	require.Equal(t, &rs, got)
	gotDL, err := d.DLState(opts.FromNw.OperatorContainers)
	require.NoError(t, err)
	require.Equal(t, AccessTN, gotDL.Legs[0].Leg)
}

func TestFullRuleFitsOneContainer(t *testing.T) {
	t.Parallel()

	full := fullRuleSet()
	rs := full
	rs.Rules = []Rule{full.Rules[0], full.Rules[len(full.Rules)-1]}
	cs, err := Encoder{PLMN: testPLMN}.RuleSet(rs)
	require.NoError(t, err)
	// header and Probe in the first container; the full rule cannot join them
	// and opens the second, which it shares with the DS catch-all.
	require.Len(t, cs, 2)
	require.LessOrEqual(t, len(cs[1].Contents), MaxContainerContents)

	d, _ := recordingDecoder(testPLMN)
	got, err := d.RuleSet(cs[:1])
	require.ErrorIs(t, err, ErrRuleCountMismatch, "the first container holds no rule")
	require.Nil(t, got)
	got, err = d.RuleSet(cs)
	require.NoError(t, err)
	require.Equal(t, &rs, got)
}
