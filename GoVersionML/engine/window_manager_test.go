// window_manager_test.go verifies time-window flushing behavior under both
// assume-ordered and strict-EOF flush policies.
package engine

import (
	"testing"

	"goversion/models"
)

func TestNetflowWindowManager_AssumeOrdered(t *testing.T) {
	wm := NewNetflowWindowManager(WindowFlushPolicy{Mode: WindowFlushAssumeOrdered})

	t0 := "2023-01-12T12:00:00.000"
	rec1 := models.NetflowRecord{
		First:    t0,
		Last:     t0,
		Src4Addr: "1.2.3.4",
		Dst4Addr: "5.6.7.8",
	}

	flushed1 := wm.ProcessRecords([]models.NetflowRecord{rec1})
	if len(flushed1) != 0 {
		t.Errorf("expected no flushed stats, got %d", len(flushed1))
	}

	t1 := "2023-01-12T12:11:00.000"
	rec2 := models.NetflowRecord{
		First:    t1,
		Last:     t1,
		Src4Addr: "1.2.3.4",
		Dst4Addr: "5.6.7.8",
	}

	flushed2 := wm.ProcessRecords([]models.NetflowRecord{rec2})
	if len(flushed2) != 2 {
		t.Errorf("expected 2 flushed stats (12:00 window for src and dst), got %d", len(flushed2))
	} else if flushed2[0].IP != ParseIPv4Val("1.2.3.4") && flushed2[1].IP != ParseIPv4Val("1.2.3.4") {
		t.Errorf("expected flushed stats to include 1.2.3.4")
	}

	flushedFinal := wm.FlushFinal()
	if len(flushedFinal) != 2 {
		t.Errorf("expected 2 final flushed stats, got %d", len(flushedFinal))
	}
}

func TestNetflowWindowManager_StrictEOF(t *testing.T) {
	wm := NewNetflowWindowManager(WindowFlushPolicy{Mode: WindowFlushStrictEOF})

	rec1 := models.NetflowRecord{
		First:    "2023-01-12T12:00:00.000",
		Last:     "2023-01-12T12:00:00.000",
		Src4Addr: "1.2.3.4",
	}
	rec2 := models.NetflowRecord{
		First:    "2023-01-12T12:11:00.000",
		Last:     "2023-01-12T12:11:00.000",
		Src4Addr: "1.2.3.4",
	}

	flushed := wm.ProcessRecords([]models.NetflowRecord{rec1, rec2})
	if len(flushed) != 0 {
		t.Errorf("expected 0 flushed stats during StrictEOF processing, got %d", len(flushed))
	}

	flushedFinal := wm.FlushFinal()
	if len(flushedFinal) != 2 {
		t.Errorf("expected 2 flushed stats at EOF, got %d", len(flushedFinal))
	}
}

func ParseIPv4Val(s string) uint32 {
	ip, _ := ParseIPv4(s)
	return ip
}
