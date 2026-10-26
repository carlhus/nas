// Package dualsteer encodes and decodes the DualSteer (DS) messages carried in
// ePCO operator-specific containers FF00H-FF03H, and checks a DS rule set's
// structure. The SMF and the DualSteer device share this one encoding.
//
// Every container starts with the PLMN (3 bytes, coded as LAI octets 2-4) and a
// format version (1 byte), followed by TLV records (T 1 byte, L 1 byte, V).
// Values are big-endian. Records of an unknown type are skipped; a container
// whose PLMN does not match or whose format version is unknown is ignored.
// A record never spans containers: a rule set too large for one container is
// sent as several FF01H containers in order, with the header record first.
package dualsteer

import (
	"fmt"
	"net/netip"
)

// Operator-specific ePCO container IDs, TS 24.008 10.5.6.3.1.
const (
	ContainerCapability    uint16 = 0xFF00 // UE -> NW
	ContainerRuleSet       uint16 = 0xFF01 // NW -> UE
	ContainerSwitchRequest uint16 = 0xFF02 // UE -> NW
	ContainerDLState       uint16 = 0xFF03 // NW -> UE
)

// FormatVersion is the container format this package writes and reads.
// It changes only for incompatible changes.
const FormatVersion uint8 = 1

const (
	// MaxContainerContents is the ePCO container length limit (1-octet length).
	MaxContainerContents = 255
	containerPrefixLen   = 4 // PLMN + format version
	// MaxRecordsLen is the room left for TLV records in one container.
	MaxRecordsLen = MaxContainerContents - containerPrefixLen
)

// Record types. One namespace for every container.
const (
	recRuleSetHeader  uint8 = 0x01 // FF01H: version, rule count, transmission mode, device parameter sub-TLVs
	recProbeIPv4      uint8 = 0x02 // FF01H: responder IPv4, responder port, TN probe port, NTN probe port
	recRule           uint8 = 0x03 // FF01H: rule ID, precedence, steering mode, rule sub-TLVs
	recSwitchHeader   uint8 = 0x10 // FF02H: version, trigger
	recSwitchRuleIDs  uint8 = 0x11 // FF02H: rule IDs
	recMeasurement    uint8 = 0x12 // FF02H: access, RTT_ewma, loss, consecutive timeouts
	recDLStateHeader  uint8 = 0x20 // FF03H: version, result
	recDLStateEntries uint8 = 0x21 // FF03H: (rule ID, DL Leg) pairs
)

// Sub-TLV types inside a rule record.
const (
	subPacketFilter uint8 = 0x01 // TS 24.501 packet filter contents
	subActiveLeg    uint8 = 0x02 // AS: active Leg
	subPriority     uint8 = 0x03 // PB: preferred Leg, maxRtt, maxLoss, RTT margin, loss margin
	subParamBase    uint8 = 0x40 // device parameter overrides, see param* below
)

// Device parameter sub-TLV types, used in the rule-set header and as rule overrides.
const (
	paramProbeInterval uint8 = subParamBase + iota // uint16 ms
	paramK                                         // uint8
	paramTimeoutFloor                              // uint16 ms
	paramTRestore                                  // uint16 ms
	paramMinDwell                                  // uint16 ms
	paramHoldDown                                  // uint16 ms
	paramDelta                                     // uint16 ms
	paramN                                         // uint8
)

// TS 24.501 Table 9.11.4.13.1 packet filter component types allowed in a DS rule.
const (
	compMatchAll        uint8 = 0x01
	compIPv4Remote      uint8 = 0x10
	compProtocol        uint8 = 0x30
	compLocalPort       uint8 = 0x40
	compLocalPortRange  uint8 = 0x41
	compRemotePort      uint8 = 0x50
	compRemotePortRange uint8 = 0x51
)

const (
	// CatchAllRuleID and CatchAllPrecedence are fixed for the DS catch-all.
	CatchAllRuleID     uint8 = 255
	CatchAllPrecedence uint8 = 255
	// MaxRules is the most rules a rule set holds, not counting the DS catch-all.
	MaxRules = 77
	// MaxPacketFilters is the most packet filters in one rule.
	MaxPacketFilters = 8
	// maxRuleLegs is the most (rule ID, DL Leg) pairs: every rule and the DS catch-all.
	maxRuleLegs = MaxRules + 1
)

// PLMN is MCC+MNC coded as LAI octets 2-4 (TS 24.008 10.5.1.3).
type PLMN [3]byte

// NewPLMN codes a decimal MCC (3 digits) and MNC (2 or 3 digits).
func NewPLMN(mcc, mnc string) (PLMN, error) {
	if len(mcc) != 3 || (len(mnc) != 2 && len(mnc) != 3) {
		return PLMN{}, fmt.Errorf("dualsteer: bad PLMN %q/%q", mcc, mnc)
	}
	d := make([]byte, 0, 6)
	for _, c := range []byte(mcc + mnc) {
		if c < '0' || c > '9' {
			return PLMN{}, fmt.Errorf("dualsteer: bad PLMN %q/%q", mcc, mnc)
		}
		d = append(d, c-'0')
	}
	mnc3 := byte(0xF)
	if len(d) == 6 {
		mnc3 = d[5]
	}
	return PLMN{d[1]<<4 | d[0], mnc3<<4 | d[2], d[4]<<4 | d[3]}, nil
}

// Access names a Leg by its access type.
type Access uint8

const (
	AccessTN  Access = 1
	AccessNTN Access = 2
)

func (a Access) valid() bool { return a == AccessTN || a == AccessNTN }

// TransmissionMode is Simultaneous or Non-simultaneous transmission.
type TransmissionMode uint8

const (
	TransmissionSimultaneous    TransmissionMode = 1
	TransmissionNonSimultaneous TransmissionMode = 2
)

// SteeringMode is a DS rule's Steering mode.
type SteeringMode uint8

const (
	SteeringActiveStandby SteeringMode = 1 // AS
	SteeringSmallestDelay SteeringMode = 2 // SD
	SteeringPriorityBased SteeringMode = 3 // PB
)

// Trigger is why the device asks for a Switching.
type Trigger uint8

const (
	TriggerReactive   Trigger = 1
	TriggerPredictive Trigger = 2
	TriggerBetterPath Trigger = 3
	TriggerThreshold  Trigger = 4
	TriggerRestore    Trigger = 5
)

// Result is the outcome carried in FF03H. The network uses 0 when it sends
// FF03H on its own.
type Result uint8

const (
	ResultAccepted                  Result = 0
	ResultNoOp                      Result = 1
	ResultUnknownRule               Result = 2
	ResultStaleVersion              Result = 3
	ResultLegNotAllowed             Result = 4
	ResultLegUnavailable            Result = 5
	ResultMinDwell                  Result = 6
	ResultTriggerInconsistent       Result = 7
	ResultNonSimultaneousIncomplete Result = 8
)

// DeviceParams are the device-level DS parameters. Times are in ms.
type DeviceParams struct {
	ProbeInterval uint16
	K             uint8 // consecutive Probe timeouts that make a Leg unavailable
	TimeoutFloor  uint16
	TRestore      uint16
	MinDwell      uint16
	HoldDown      uint16
	Delta         uint16 // SD: RTT difference that favours the other Leg
	N             uint8  // consecutive samples a condition must hold
}

// DefaultDeviceParams returns the defaults in spec #19 section 10. A rule-set
// header that omits a parameter means its default.
func DefaultDeviceParams() DeviceParams {
	return DeviceParams{
		ProbeInterval: 200,
		K:             3,
		TimeoutFloor:  100,
		TRestore:      3000,
		MinDwell:      3000,
		HoldDown:      5000,
		Delta:         15,
		N:             3,
	}
}

// DeviceParamOverrides overrides device parameters on one rule; nil keeps the
// rule set's value.
type DeviceParamOverrides struct {
	ProbeInterval *uint16
	K             *uint8
	TimeoutFloor  *uint16
	TRestore      *uint16
	MinDwell      *uint16
	HoldDown      *uint16
	Delta         *uint16
	N             *uint8
}

// Apply returns p with the overrides set in o.
func (o DeviceParamOverrides) Apply(p DeviceParams) DeviceParams {
	set(&p.ProbeInterval, o.ProbeInterval)
	set(&p.K, o.K)
	set(&p.TimeoutFloor, o.TimeoutFloor)
	set(&p.TRestore, o.TRestore)
	set(&p.MinDwell, o.MinDwell)
	set(&p.HoldDown, o.HoldDown)
	set(&p.Delta, o.Delta)
	set(&p.N, o.N)
	return p
}

func set[T any](dst *T, v *T) {
	if v != nil {
		*dst = *v
	}
}

// Probe tells the device where its Probes go.
type Probe struct {
	Responder     netip.Addr // IPv4
	ResponderPort uint16
	TNPort        uint16 // device-side probe port on the TN Leg
	NTNPort       uint16 // device-side probe port on the NTN Leg
}

// PortRange is an inclusive port range; Low == High is a single port.
type PortRange struct {
	Low, High uint16
}

// PacketFilter is one bidirectional TS 24.501 packet filter. Only the
// components DS rules allow are expressible. Zero fields are absent.
type PacketFilter struct {
	MatchAll   bool
	Remote     netip.Prefix // IPv4 remote address and mask
	Protocol   *uint8       // protocol identifier
	LocalPort  *PortRange
	RemotePort *PortRange
}

// PriorityParams are the Priority-based mode parameters. The device leaves the
// preferred Leg when RTT exceeds MaxRTT or loss exceeds MaxLoss, and returns
// only while RTT < MaxRTT-RTTMargin and loss < MaxLoss-LossMargin. RTT values
// are in ms, loss values in permille; each margin must be below its threshold.
type PriorityParams struct {
	PreferredLeg Access
	MaxRTT       uint16
	MaxLoss      uint16
	RTTMargin    uint16
	LossMargin   uint16
}

// Rule is one DS rule.
type Rule struct {
	ID         uint8
	Precedence uint8
	Filters    []PacketFilter
	Mode       SteeringMode
	ActiveLeg  Access         // AS only
	Priority   PriorityParams // PB only
	Overrides  DeviceParamOverrides
}

// RuleSet is the whole DS rule set (FF01H). It is always sent and replaced as
// a whole.
type RuleSet struct {
	Version      uint8
	Transmission TransmissionMode
	Params       DeviceParams
	Probe        *Probe
	Rules        []Rule // including the DS catch-all
}

// Measurement is one Leg's measurement snapshot.
type Measurement struct {
	RTT                 uint16 // RTT_ewma, ms
	Loss                uint16 // permille
	ConsecutiveTimeouts uint8
}

// SwitchRequest (FF02H) asks to move a set of Services to the Leg that carries
// the request.
type SwitchRequest struct {
	Version uint8
	Trigger Trigger
	RuleIDs []uint8
	TN, NTN Measurement
}

// RuleLeg is one rule's current DL Leg.
type RuleLeg struct {
	RuleID uint8
	Leg    Access
}

// DLState (FF03H) reports a result and the DL Leg of every rule.
type DLState struct {
	Version uint8
	Result  Result
	Legs    []RuleLeg
}
