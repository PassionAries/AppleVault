package machine

import (
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
)

func TestUsableMacAddress(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address net.HardwareAddr
		valid   bool
	}{
		{"missing", nil, false},
		{"short", net.HardwareAddr{0, 1}, false},
		{"EUI64", net.HardwareAddr{0, 1, 2, 3, 4, 5, 6, 7}, false},
		{"zero", net.HardwareAddr{0, 0, 0, 0, 0, 0}, false},
		{"redacted", net.HardwareAddr{2, 0, 0, 0, 0, 0}, false},
		{"broadcast", net.HardwareAddr{255, 255, 255, 255, 255, 255}, false},
		{"multicast", net.HardwareAddr{1, 0, 0x5e, 0, 0, 1}, false},
		{"unicast", net.HardwareAddr{0, 1, 2, 3, 4, 5}, true},
		{"locally administered", net.HardwareAddr{2, 1, 2, 3, 4, 5}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := usableMacAddress(tc.address); got != tc.valid {
				t.Fatalf("valid = %v, want %v", got, tc.valid)
			}
		})
	}
}

func TestMacAddressIsIndependentOfAdapterOrderAndState(t *testing.T) {
	interfaces := []net.Interface{
		{Name: "virtual", Index: 1, Flags: net.FlagUp, HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 1}},
		{Name: "wired", Index: 20, HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 3}},
		{Name: "wireless", Index: 10, Flags: net.FlagUp, HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 2}},
	}
	lookup := func(iface net.Interface) (macAddressCandidate, error) {
		priority := macPriorityPhysical
		if iface.Name == "virtual" {
			priority = macPriorityFallback
		}
		return macAddressCandidate{address: iface.HardwareAddr, priority: priority}, nil
	}
	for range 3 {
		for _, reversed := range []bool{false, true} {
			input := slices.Clone(interfaces)
			if reversed {
				slices.Reverse(input)
			}
			address, err := selectMacAddress(input, lookup)
			if err != nil || address != "00:00:00:00:00:02" {
				t.Fatalf("selection = %q, %v", address, err)
			}
		}
		interfaces = append(interfaces[1:], interfaces[0])
		for i := range interfaces {
			interfaces[i].Index += 100
			interfaces[i].Flags ^= net.FlagUp
		}
	}
}

func TestMacAddressSkipsInvalidInterfacesAndRetainsErrors(t *testing.T) {
	lookupErr := errors.New("hardware unavailable")
	interfaces := []net.Interface{
		{Name: "loopback", Flags: net.FlagLoopback},
		{Name: "tunnel", Flags: net.FlagPointToPoint},
		{Name: "unavailable"},
		{Name: "redacted", HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 0}},
		{Name: "fallback", HardwareAddr: net.HardwareAddr{2, 1, 2, 3, 4, 5}},
	}
	lookup := func(iface net.Interface) (macAddressCandidate, error) {
		if iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			t.Fatal("looked up an excluded interface")
		}
		if iface.Name == "unavailable" {
			return macAddressCandidate{}, lookupErr
		}
		return macAddressCandidate{address: iface.HardwareAddr, priority: macPriorityFallback}, nil
	}
	address, err := selectMacAddress(interfaces, lookup)
	if err != nil || address != "02:01:02:03:04:05" {
		t.Fatalf("fallback = %q, %v", address, err)
	}
	_, err = selectMacAddress(interfaces[:4], lookup)
	if !errors.Is(err, lookupErr) {
		t.Fatalf("lookup cause lost: %v", err)
	}
	_, err = selectMacAddress(nil, nil)
	if err == nil || err.Error() != "could not find network interfaces with a valid mac address" {
		t.Fatalf("missing address error = %v", err)
	}
}

func TestMachineResolvesIdentityOnceConcurrently(t *testing.T) {
	var calls atomic.Int32
	m := &machine{interfaces: func() ([]net.Interface, error) {
		last := byte(calls.Add(1))
		return []net.Interface{{Index: 2147483647, Name: "ipatool-test", HardwareAddr: net.HardwareAddr{2, 1, 2, 3, 4, last}}}, nil
	}}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			address, err := m.MacAddress()
			if err != nil || address != "02:01:02:03:04:01" {
				t.Errorf("identity = %q, %v", address, err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("resolved %d times", calls.Load())
	}
	_, _ = m.MacAddress()
	if calls.Load() != 1 {
		t.Fatal("identity changed on subsequent call")
	}
}

func TestMachineCachesEnumerationError(t *testing.T) {
	lookupErr := errors.New("interfaces unavailable")
	calls := 0
	m := &machine{interfaces: func() ([]net.Interface, error) { calls++; return nil, lookupErr }}
	for range 2 {
		address, err := m.MacAddress()
		if address != "" || !errors.Is(err, lookupErr) {
			t.Fatalf("identity = %q, %v", address, err)
		}
	}
	if calls != 1 {
		t.Fatalf("resolved %d times", calls)
	}
}
