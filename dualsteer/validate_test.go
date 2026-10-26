package dualsteer

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/nas/ie"
)

func TestDecoderDropsInvalidRuleSet(t *testing.T) {
	t.Parallel()

	const (
		probe    = "\x02\x0a\x0a\x3c\x00\x01\x27\x0f\x9c\x41\x9c\x42"
		catchAll = "\x03\x06\xff\xff\x02\x01\x01\x01"
		udpRule  = "\x03\x07\x01\x0a\x02\x01\x02\x30\x11" // rule 1, precedence 10, SD, UDP
		tcpRule  = "\x03\x07\x02\x0a\x02\x01\x02\x30\x06" // rule 2, precedence 10, SD, TCP
	)
	header := func(count uint8) string { return string([]byte{0x01, 0x03, 0x05, count, 0x01}) }

	testCases := []struct {
		name    string
		records []string // one string per FF01H container
		want    error
	}{
		{"count above rules", []string{header(3) + probe + catchAll}, ErrRuleCountMismatch},
		{"count below rules", []string{header(1) + probe + udpRule + catchAll}, ErrRuleCountMismatch},
		{"count across containers", []string{header(3) + probe, catchAll, udpRule}, ErrRuleCountMismatch},
		{"no DS catch-all", []string{header(1) + probe + udpRule}, ErrNoCatchAll},
		{"no Probe", []string{header(1) + catchAll}, ErrNoProbe},
		{"duplicate precedence", []string{header(3) + probe + udpRule + tcpRule + catchAll}, ErrDuplicatePrecedence},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var cs []ie.OperatorContainer
			for _, r := range tc.records {
				cs = append(cs, ie.OperatorContainer{ID: 0xff01, Contents: append([]byte{0x02, 0xf8, 0x39, 0x01}, r...)})
			}
			d, _ := recordingDecoder(testPLMN)
			got, err := d.RuleSet(cs)
			require.ErrorIs(t, err, tc.want)
			require.ErrorIs(t, err, ErrInvalidRuleSet)
			require.Nil(t, got)
		})
	}
}

func TestRuleSetIgnoredContainerDropsWholeSet(t *testing.T) {
	t.Parallel()

	cs, err := Encoder{PLMN: testPLMN}.RuleSet(fullRuleSet())
	require.NoError(t, err)
	cs[2].Contents = append([]byte{0x64, 0xf6, 0x29}, cs[2].Contents[3:]...) // another PLMN

	d, ignored := recordingDecoder(testPLMN)
	_, err = d.RuleSet(cs)
	require.ErrorIs(t, err, ErrRuleCountMismatch)
	require.Len(t, *ignored, 1)
	require.ErrorIs(t, (*ignored)[0].err, ErrPLMNMismatch)
}

func TestValidate(t *testing.T) {
	t.Parallel()

	valid := func() RuleSet {
		return RuleSet{
			Version:      1,
			Transmission: TransmissionSimultaneous,
			Params:       DefaultDeviceParams(),
			Probe:        testProbe,
			Rules: []Rule{
				{ID: 1, Precedence: 0, Filters: []PacketFilter{{Protocol: new(uint8(17))}}, Mode: SteeringSmallestDelay},
				{
					ID: CatchAllRuleID, Precedence: CatchAllPrecedence, Filters: []PacketFilter{{MatchAll: true}},
					Mode: SteeringActiveStandby, ActiveLeg: AccessTN,
				},
			},
		}
	}
	base := valid()
	require.NoError(t, base.Validate())
	full := fullRuleSet()
	require.NoError(t, full.Validate())

	testCases := []struct {
		name   string
		mutate func(*RuleSet)
		want   error
	}{
		{"no Probe", func(rs *RuleSet) { rs.Probe = nil }, ErrNoProbe},
		{"IPv6 Probe responder", func(rs *RuleSet) {
			rs.Probe = &Probe{Responder: netip.MustParseAddr("2001:db8::1")}
		}, ErrInvalidRuleSet},
		{"no DS catch-all", func(rs *RuleSet) { rs.Rules = rs.Rules[:1] }, ErrNoCatchAll},
		{"duplicate precedence", func(rs *RuleSet) {
			rs.Rules = append(rs.Rules, Rule{ID: 2, Precedence: 0, Filters: rs.Rules[0].Filters, Mode: SteeringSmallestDelay})
		}, ErrDuplicatePrecedence},
		{"duplicate rule ID", func(rs *RuleSet) {
			rs.Rules = append(rs.Rules, Rule{ID: 1, Precedence: 1, Filters: rs.Rules[0].Filters, Mode: SteeringSmallestDelay})
		}, ErrInvalidRuleSet},
		{"78 rules", func(rs *RuleSet) {
			*rs = fullRuleSet()
			rs.Rules = append(rs.Rules,
				Rule{ID: 200, Precedence: 200, Filters: rs.Rules[0].Filters, Mode: SteeringSmallestDelay})
		}, ErrTooManyRules},
		{"catch-all not match-all", func(rs *RuleSet) {
			rs.Rules[1].Filters = []PacketFilter{{Protocol: new(uint8(6))}}
		}, ErrInvalidRuleSet},
		{"catch-all precedence", func(rs *RuleSet) { rs.Rules[1].Precedence = 100 }, ErrInvalidRuleSet},
		{"rule with precedence 255", func(rs *RuleSet) { rs.Rules[0].Precedence = 255 }, ErrInvalidRuleSet},
		{"rule ID 0", func(rs *RuleSet) { rs.Rules[0].ID = 0 }, ErrInvalidRuleSet},
		{"no packet filter", func(rs *RuleSet) { rs.Rules[0].Filters = nil }, ErrInvalidRuleSet},
		{"9 packet filters", func(rs *RuleSet) {
			rs.Rules[0].Filters = make([]PacketFilter, 9)
			for i := range rs.Rules[0].Filters {
				rs.Rules[0].Filters[i].Protocol = new(uint8(i))
			}
		}, ErrInvalidRuleSet},
		{"empty packet filter", func(rs *RuleSet) { rs.Rules[0].Filters = []PacketFilter{{}} }, ErrInvalidRuleSet},
		{"IPv6 remote", func(rs *RuleSet) {
			rs.Rules[0].Filters = []PacketFilter{{Remote: netip.MustParsePrefix("2001:db8::/32")}}
		}, ErrInvalidRuleSet},
		{"inverted port range", func(rs *RuleSet) {
			rs.Rules[0].Filters = []PacketFilter{{RemotePort: &PortRange{Low: 9, High: 8}}}
		}, ErrInvalidRuleSet},
		{"AS without active Leg", func(rs *RuleSet) { rs.Rules[1].ActiveLeg = 0 }, ErrInvalidRuleSet},
		{"PB without preferred Leg", func(rs *RuleSet) { rs.Rules[0].Mode = SteeringPriorityBased }, ErrInvalidRuleSet},
		{"unknown Steering mode", func(rs *RuleSet) { rs.Rules[0].Mode = 4 }, ErrInvalidRuleSet},
		{"unknown transmission mode", func(rs *RuleSet) { rs.Transmission = 0 }, ErrInvalidRuleSet},
		{"K 0", func(rs *RuleSet) { rs.Params.K = 0 }, ErrInvalidRuleSet},
		{"override N 0", func(rs *RuleSet) { rs.Rules[0].Overrides.N = new(uint8(0)) }, ErrInvalidRuleSet},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rs := valid()
			tc.mutate(&rs)
			require.ErrorIs(t, rs.Validate(), tc.want)

			_, err := Encoder{PLMN: testPLMN}.RuleSet(rs)
			require.ErrorIs(t, err, tc.want, "encoder refuses what Validate rejects")
		})
	}
}
