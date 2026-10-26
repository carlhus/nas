package dualsteer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/nas/ie"
)

// 208/93, as free5gc's default config.
var testPLMN = PLMN{0x02, 0xf8, 0x39}

func TestNewPLMN(t *testing.T) {
	t.Parallel()

	p, err := NewPLMN("208", "93")
	require.NoError(t, err)
	require.Equal(t, testPLMN, p)

	p, err = NewPLMN("466", "011")
	require.NoError(t, err)
	require.Equal(t, PLMN{0x64, 0x16, 0x10}, p)

	_, err = NewPLMN("20", "93")
	require.Error(t, err)
}

type ignoredContainer struct {
	id  uint16
	err error
}

func recordingDecoder(plmn PLMN) (*Decoder, *[]ignoredContainer) {
	var ignored []ignoredContainer
	return &Decoder{
		PLMN: plmn,
		Ignored: func(id uint16, err error) {
			ignored = append(ignored, ignoredContainer{id, err})
		},
	}, &ignored
}

func TestCapability(t *testing.T) {
	t.Parallel()

	c := Encoder{PLMN: testPLMN}.Capability()
	require.Equal(t, ie.OperatorContainer{ID: 0xff00, Contents: []byte{0x02, 0xf8, 0x39, 0x01}}, c)

	d, _ := recordingDecoder(testPLMN)
	require.True(t, d.Capability([]ie.OperatorContainer{{ID: 0xff03, Contents: []byte{0x02, 0xf8, 0x39, 0x01}}, c}))
	require.False(t, d.Capability(nil))
}

func TestDecoderIgnoresForeignContainers(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		contents []byte
		reason   error
	}{
		{"PLMN mismatch", []byte{0x64, 0xf6, 0x29, 0x01}, ErrPLMNMismatch},
		{"unknown format version", []byte{0x02, 0xf8, 0x39, 0x02}, ErrUnknownFormatVersion},
		{"too short", []byte{0x02, 0xf8}, ErrMalformed},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d, ignored := recordingDecoder(testPLMN)
			require.False(t, d.Capability([]ie.OperatorContainer{{ID: 0xff00, Contents: tc.contents}}))
			require.Len(t, *ignored, 1)
			require.Equal(t, uint16(0xff00), (*ignored)[0].id)
			require.ErrorIs(t, (*ignored)[0].err, tc.reason)
		})
	}
}

func TestDLStateRoundTrip(t *testing.T) {
	t.Parallel()

	s := DLState{
		Version: 7,
		Result:  ResultMinDwell,
		Legs:    []RuleLeg{{RuleID: 1, Leg: AccessNTN}, {RuleID: 255, Leg: AccessTN}},
	}
	c, err := Encoder{PLMN: testPLMN}.DLState(s)
	require.NoError(t, err)
	require.Equal(t, ie.OperatorContainer{ID: 0xff03, Contents: []byte{
		0x02, 0xf8, 0x39, 0x01,
		0x20, 0x02, 0x07, 0x06, // header: version 7, result minDwell
		0x21, 0x04, 0x01, 0x02, 0xff, 0x01, // rule 1 on NTN, rule 255 on TN
	}}, c)

	d, _ := recordingDecoder(testPLMN)
	got, err := d.DLState([]ie.OperatorContainer{c})
	require.NoError(t, err)
	require.Equal(t, &s, got)
}

func TestDLStateNoneFound(t *testing.T) {
	t.Parallel()

	d, _ := recordingDecoder(testPLMN)
	got, err := d.DLState([]ie.OperatorContainer{Encoder{PLMN: testPLMN}.Capability()})
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestDLStateFitsAllRulesInOneContainer(t *testing.T) {
	t.Parallel()

	s := DLState{Version: 1, Result: ResultAccepted}
	for id := range uint8(MaxRules) {
		s.Legs = append(s.Legs, RuleLeg{RuleID: id + 1, Leg: AccessTN})
	}
	s.Legs = append(s.Legs, RuleLeg{RuleID: CatchAllRuleID, Leg: AccessNTN})
	require.Len(t, s.Legs, 78)

	c, err := Encoder{PLMN: testPLMN}.DLState(s)
	require.NoError(t, err)
	require.LessOrEqual(t, len(c.Contents), MaxContainerContents)

	d, _ := recordingDecoder(testPLMN)
	got, err := d.DLState([]ie.OperatorContainer{c})
	require.NoError(t, err)
	require.Equal(t, &s, got)
}

func TestDecoderSkipsUnknownRecords(t *testing.T) {
	t.Parallel()

	c := ie.OperatorContainer{ID: 0xff03, Contents: []byte{
		0x02, 0xf8, 0x39, 0x01,
		0x7f, 0x03, 0xaa, 0xbb, 0xcc, // unknown record
		0x20, 0x02, 0x07, 0x00,
		0x7e, 0x00, // unknown empty record
		0x21, 0x02, 0xff, 0x02,
	}}
	d, _ := recordingDecoder(testPLMN)
	got, err := d.DLState([]ie.OperatorContainer{c})
	require.NoError(t, err)
	require.Equal(t, &DLState{Version: 7, Result: ResultAccepted, Legs: []RuleLeg{{RuleID: 255, Leg: AccessNTN}}}, got)
}

func TestDLStateMalformed(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		records []byte
	}{
		{"no header", []byte{0x21, 0x02, 0xff, 0x02}},
		{"truncated TLV", []byte{0x20, 0x02, 0x07, 0x00, 0x21, 0x04, 0xff, 0x02}},
		{"odd entries", []byte{0x20, 0x02, 0x07, 0x00, 0x21, 0x01, 0xff}},
		{"short header", []byte{0x20, 0x01, 0x07}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := ie.OperatorContainer{ID: 0xff03, Contents: append([]byte{0x02, 0xf8, 0x39, 0x01}, tc.records...)}
			d, _ := recordingDecoder(testPLMN)
			_, err := d.DLState([]ie.OperatorContainer{c})
			require.ErrorIs(t, err, ErrMalformed)
		})
	}
}

func TestDLStateEmptyContainerIsMalformed(t *testing.T) {
	t.Parallel()

	d, _ := recordingDecoder(testPLMN)
	_, err := d.DLState([]ie.OperatorContainer{{ID: 0xff03, Contents: []byte{0x02, 0xf8, 0x39, 0x01}}})
	require.ErrorIs(t, err, ErrMalformed)
}

func TestSwitchRequestRoundTrip(t *testing.T) {
	t.Parallel()

	r := SwitchRequest{
		Version: 3,
		Trigger: TriggerPredictive,
		RuleIDs: []uint8{1, 4, 255},
		TN:      Measurement{RTT: 12, Loss: 0, ConsecutiveTimeouts: 0},
		NTN:     Measurement{RTT: 0x0123, Loss: 25, ConsecutiveTimeouts: 2},
	}
	c, err := Encoder{PLMN: testPLMN}.SwitchRequest(r)
	require.NoError(t, err)
	require.Equal(t, ie.OperatorContainer{ID: 0xff02, Contents: []byte{
		0x02, 0xf8, 0x39, 0x01,
		0x10, 0x02, 0x03, 0x02, // version 3, predictive
		0x11, 0x03, 0x01, 0x04, 0xff, // rule IDs
		0x12, 0x06, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x00, // TN: 12 ms, 0 permille, 0 timeouts
		0x12, 0x06, 0x02, 0x01, 0x23, 0x00, 0x19, 0x02, // NTN: 291 ms, 25 permille, 2 timeouts
	}}, c)

	d, _ := recordingDecoder(testPLMN)
	got, err := d.SwitchRequest([]ie.OperatorContainer{c})
	require.NoError(t, err)
	require.Equal(t, &r, got)
}

func TestSwitchRequestMalformed(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		records []byte
	}{
		{"no header", []byte{0x11, 0x01, 0x01, 0x12, 0x06, 0x01, 0, 0, 0, 0, 0, 0x12, 0x06, 0x02, 0, 0, 0, 0, 0}},
		{"no NTN measurement", []byte{0x10, 0x02, 0x03, 0x01, 0x11, 0x01, 0x01, 0x12, 0x06, 0x01, 0, 0, 0, 0, 0}},
		{"unknown access", []byte{
			0x10, 0x02, 0x03, 0x01, 0x11, 0x01, 0x01,
			0x12, 0x06, 0x01, 0, 0, 0, 0, 0, 0x12, 0x06, 0x03, 0, 0, 0, 0, 0,
		}},
		{"no rule IDs", []byte{0x10, 0x02, 0x03, 0x01, 0x12, 0x06, 0x01, 0, 0, 0, 0, 0, 0x12, 0x06, 0x02, 0, 0, 0, 0, 0}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := ie.OperatorContainer{ID: 0xff02, Contents: append([]byte{0x02, 0xf8, 0x39, 0x01}, tc.records...)}
			d, _ := recordingDecoder(testPLMN)
			_, err := d.SwitchRequest([]ie.OperatorContainer{c})
			require.ErrorIs(t, err, ErrMalformed)
		})
	}
}
