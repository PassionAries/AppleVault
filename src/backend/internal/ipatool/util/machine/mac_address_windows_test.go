package machine

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsMacUsesPermanentAddress(t *testing.T) {
	row := windows.MibIfRow2{PhysicalAddressLength: 6, Type: windows.IF_TYPE_ETHERNET_CSMACD, InterfaceAndOperStatusFlags: 1}
	copy(row.PhysicalAddress[:], []byte{2, 1, 2, 3, 4, 5})
	copy(row.PermanentPhysicalAddress[:], []byte{0, 1, 2, 3, 4, 5})
	for _, state := range []uint32{windows.IfOperStatusUp, windows.IfOperStatusDown} {
		row.OperStatus = state
		candidate := macAddressFromWindowsRow(row)
		if candidate.address.String() != "00:01:02:03:04:05" || candidate.priority != macPriorityPhysical {
			t.Fatalf("permanent address not preferred: %+v", candidate)
		}
	}
	clear(row.PermanentPhysicalAddress[:])
	if got := macAddressFromWindowsRow(row).address.String(); got != "02:01:02:03:04:05" {
		t.Fatalf("fallback = %q", got)
	}
	for _, length := range []uint32{0, 8, 100} {
		row.PhysicalAddressLength = length
		if got := macAddressFromWindowsRow(row).address; len(got) != 0 {
			t.Fatalf("accepted length %d", length)
		}
	}
}

func TestWindowsMacPhysicalPriority(t *testing.T) {
	for _, tc := range []struct {
		name         string
		flags        uint8
		kind, medium uint32
		priority     int
	}{
		{"wifi", 1, windows.IF_TYPE_IEEE80211, 9, macPriorityPhysical},
		{"virtual", 0, windows.IF_TYPE_ETHERNET_CSMACD, 0, macPriorityFallback},
		{"filter", 3, windows.IF_TYPE_ETHERNET_CSMACD, 0, macPriorityFallback},
		{"bluetooth", 1, windows.IF_TYPE_ETHERNET_CSMACD, 10, macPriorityFallback},
		{"tunnel", 1, windows.IF_TYPE_TUNNEL, 0, macPriorityFallback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := windows.MibIfRow2{PhysicalAddressLength: 6, Type: tc.kind, PhysicalMediumType: tc.medium, InterfaceAndOperStatusFlags: tc.flags}
			copy(row.PhysicalAddress[:], []byte{0, 1, 2, 3, 4, 5})
			if got := macAddressFromWindowsRow(row).priority; got != tc.priority {
				t.Fatalf("priority = %d, want %d", got, tc.priority)
			}
		})
	}
}
