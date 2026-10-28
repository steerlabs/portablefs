package mountlog

// FUSEOperationSlots includes stock requests and maintained go-fuse notification
// indexes through 105; unknown names have the bounded bucket zero.
const FUSEOperationSlots = 106

// MetadataStats is a bounded observational snapshot, never serving permission
// or a completion receipt. FUSE counts cover completed stock requests; opcode
// indexes retain the Linux FUSE numeric meanings; reverse notifications have
// separate attempt, failure and transport-time counters. Samples are not atomic with
// authority metrics, RTC sampling or process memory observations.
type MetadataStats struct {
	PID                  int      `json:"pid"`
	ProcessStart         string   `json:"processStart"`
	FUSEOperations       []uint64 `json:"fuseOperations"`
	Notifications        uint64   `json:"notifications"`
	NotificationNanos    uint64   `json:"notificationNanos"`
	NotificationFailures uint64   `json:"notificationFailures"`
	MetadataHits         uint64   `json:"metadataHits"`
	MetadataMisses       uint64   `json:"metadataMisses"`
	PageHits             uint64   `json:"pageHits"`
	PageMisses           uint64   `json:"pageMisses"`
	OpenHits             uint64   `json:"openHits"`
	OpenMisses           uint64   `json:"openMisses"`
	MissAbsent           uint64   `json:"missAbsent"`
	MissAttributes       uint64   `json:"missAttributes"`
	MissWithdrawn        uint64   `json:"missWithdrawn"`
	MissOwnership        uint64   `json:"missOwnership"`
	MissFinalPublication uint64   `json:"missFinalPublication"`
	SingleFlightWaits    uint64   `json:"singleFlightWaits"`
	CapacityEvictions    uint64   `json:"capacityEvictions"`
	Invalidations        uint64   `json:"invalidations"`
	PayloadBytes         int      `json:"payloadBytes"`
	PayloadLimit         int      `json:"payloadLimit"`
	Names                int      `json:"names"`
	Pages                int      `json:"pages"`
	Backings             int      `json:"backings"`
	PendingFills         int      `json:"pendingFills"`
	RTCReads             uint64   `json:"rtcReads"`
	RTCNanos             uint64   `json:"rtcNanos"`
	RTCFailures          uint64   `json:"rtcFailures"`
	ColdInstalls         uint64   `json:"coldInstalls"`
	Incarnation          uint64   `json:"incarnation"`
	Withdrawals          uint64   `json:"withdrawals"`
	WithdrawalNanos      uint64   `json:"withdrawalNanos"`
	Terminal             bool     `json:"terminal"`
}
