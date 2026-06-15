package engine

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"goversion/models"
)

const numPartitions = 64

type WindowKey struct {
	IP     uint32
	Window int64
}

type PartitionRecord struct {
	IP        uint32
	TargetIP  uint32
	FirstMs   int64
	LastMs    int64
	InBytes   int64
	InPackets int64
	Port      uint16
	Proto     uint16
	TCPFlags  uint8
	IsOut     bool
}

type Aggregator struct {
	tempDir                string
	files                  [numPartitions]*os.File
	buffers                [numPartitions][]PartitionRecord
	mutexes                [numPartitions]sync.Mutex
	timestampWarningLogged atomic.Bool
	closed                 bool
}

func NewAggregator() *Aggregator {
	dir, err := os.MkdirTemp("", "goversion_netflow_parts_*")
	if err != nil {
		log.Fatalf("failed to create temp dir for aggregator: %v", err)
	}

	a := &Aggregator{
		tempDir: dir,
	}

	for i := 0; i < numPartitions; i++ {
		path := filepath.Join(dir, fmt.Sprintf("part_%d.bin", i))
		f, err := os.Create(path)
		if err != nil {
			log.Fatalf("failed to create partition file %s: %v", path, err)
		}
		a.files[i] = f
		a.buffers[i] = make([]PartitionRecord, 0, 2048)
	}

	return a
}

func (a *Aggregator) parseTimestamp(s string) (time.Time, bool) {
	if len(s) >= 23 && s[4] == '-' && s[10] == 'T' {
		year := int(s[0]-'0')*1000 + int(s[1]-'0')*100 + int(s[2]-'0')*10 + int(s[3]-'0')
		month := int(s[5]-'0')*10 + int(s[6]-'0')
		day := int(s[8]-'0')*10 + int(s[9]-'0')
		hour := int(s[11]-'0')*10 + int(s[12]-'0')
		minute := int(s[14]-'0')*10 + int(s[15]-'0')
		second := int(s[17]-'0')*10 + int(s[18]-'0')
		msec := int(s[20]-'0')*100 + int(s[21]-'0')*10 + int(s[22]-'0')
		return time.Date(year, time.Month(month), day, hour, minute, second, msec*1000000, time.UTC), true
	}

	t, err := time.Parse("2006-01-02T15:04:05.000", s)
	if err == nil {
		return t, true
	}

	t, err = time.Parse("2006-01-02 15:04:05", s)
	if err == nil {
		return t, true
	}

	t, err = time.Parse("2006-01-02 15:04:05.000", s)
	if err == nil {
		return t, true
	}

	if a.timestampWarningLogged.CompareAndSwap(false, true) {
		log.Printf("WARNING: failed to parse timestamp %q: %v (further warnings suppressed)", s, err)
	}
	return t, false
}

func encodeTCPFlags(s string) uint8 {
	var mask uint8
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 'S':
			mask |= 1
		case 'A':
			mask |= 2
		case 'F':
			mask |= 4
		case 'R':
			mask |= 8
		case 'P':
			mask |= 16
		case 'E':
			mask |= 32
		case 'C':
			mask |= 64
		}
	}
	return mask
}

func (a *Aggregator) Update(record models.NetflowRecord) {
	first, ok := a.parseTimestamp(record.First)
	if !ok {
		return
	}
	lastMs := int64(0)
	if last, ok := a.parseTimestamp(record.Last); ok {
		lastMs = last.UnixNano() / 1e6
	}
	firstMs := first.UnixNano() / 1e6

	flags := encodeTCPFlags(record.TCPFlags)

	if record.Src4Addr != "" {
		srcIP, srcOk := ParseIPv4(record.Src4Addr)
		if srcOk {
			dstIP, _ := ParseIPv4(record.Dst4Addr)
			r := PartitionRecord{
				IP:        srcIP,
				TargetIP:  dstIP,
				FirstMs:   firstMs,
				LastMs:    lastMs,
				InBytes:   record.InBytes,
				InPackets: record.InPackets,
				Port:      uint16(record.DstPort),
				Proto:     uint16(record.Proto),
				TCPFlags:  flags,
				IsOut:     true,
			}
			a.writeToPartition(srcIP, &r)
		}
	}

	if record.Dst4Addr != "" {
		dstIP, dstOk := ParseIPv4(record.Dst4Addr)
		if dstOk {
			r := PartitionRecord{
				IP:       dstIP,
				FirstMs:  firstMs,
				Port:     uint16(record.DstPort),
				IsOut:    false,
			}
			a.writeToPartition(dstIP, &r)
		}
	}
}

func (a *Aggregator) writeToPartition(ip uint32, r *PartitionRecord) {
	pIdx := int(ip % numPartitions)
	a.mutexes[pIdx].Lock()
	defer a.mutexes[pIdx].Unlock()

	if a.closed {
		return
	}

	a.buffers[pIdx] = append(a.buffers[pIdx], *r)
	if len(a.buffers[pIdx]) >= 2048 {
		a.flushBuffer(pIdx)
	}
}

func (a *Aggregator) flushBuffer(pIdx int) {
	records := a.buffers[pIdx]
	if len(records) == 0 {
		return
	}

	bufSize := len(records) * 46
	buf := make([]byte, bufSize)
	for i, r := range records {
		offset := i * 46
		binary.BigEndian.PutUint32(buf[offset:offset+4], r.IP)
		binary.BigEndian.PutUint32(buf[offset+4:offset+8], r.TargetIP)
		binary.BigEndian.PutUint64(buf[offset+8:offset+16], uint64(r.FirstMs))
		binary.BigEndian.PutUint64(buf[offset+16:offset+24], uint64(r.LastMs))
		binary.BigEndian.PutUint64(buf[offset+24:offset+32], uint64(r.InBytes))
		binary.BigEndian.PutUint64(buf[offset+32:offset+40], uint64(r.InPackets))
		binary.BigEndian.PutUint16(buf[offset+40:offset+42], r.Port)
		binary.BigEndian.PutUint16(buf[offset+42:offset+44], r.Proto)
		buf[offset+44] = r.TCPFlags
		if r.IsOut {
			buf[offset+45] = 1
		} else {
			buf[offset+45] = 0
		}
	}

	a.files[pIdx].Write(buf)
	a.buffers[pIdx] = a.buffers[pIdx][:0]
}

func (a *Aggregator) Close() {
	if a.closed {
		return
	}
	a.closed = true
	for i := 0; i < numPartitions; i++ {
		a.mutexes[i].Lock()
		a.flushBuffer(i)
		if a.files[i] != nil {
			a.files[i].Close()
		}
		a.mutexes[i].Unlock()
	}
	if a.tempDir != "" {
		os.RemoveAll(a.tempDir)
		a.tempDir = ""
	}
}

var readerPool64k = sync.Pool{
	New: func() interface{} {
		return bufio.NewReaderSize(nil, 65536)
	},
}

func (a *Aggregator) readPartition(pIdx int, callback func(*PartitionRecord)) error {
	a.mutexes[pIdx].Lock()
	a.flushBuffer(pIdx)
	a.mutexes[pIdx].Unlock()

	f, err := os.Open(filepath.Join(a.tempDir, fmt.Sprintf("part_%d.bin", pIdx)))
	if err != nil {
		return err
	}
	defer f.Close()

	r := readerPool64k.Get().(*bufio.Reader)
	r.Reset(f)
	defer readerPool64k.Put(r)

	var buf [46]byte
	for {
		var rec PartitionRecord
		_, err := io.ReadFull(r, buf[:])
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return err
		}

		rec.IP = binary.BigEndian.Uint32(buf[0:4])
		rec.TargetIP = binary.BigEndian.Uint32(buf[4:8])
		rec.FirstMs = int64(binary.BigEndian.Uint64(buf[8:16]))
		rec.LastMs = int64(binary.BigEndian.Uint64(buf[16:24]))
		rec.InBytes = int64(binary.BigEndian.Uint64(buf[24:32]))
		rec.InPackets = int64(binary.BigEndian.Uint64(buf[32:40]))
		rec.Port = binary.BigEndian.Uint16(buf[40:42])
		rec.Proto = binary.BigEndian.Uint16(buf[42:44])
		rec.TCPFlags = buf[44]
		rec.IsOut = buf[45] == 1

		callback(&rec)
	}
	return nil
}

func (a *Aggregator) aggregatePartition(pIdx int) map[WindowKey]*IPStats {
	m := make(map[WindowKey]*IPStats)
	a.readPartition(pIdx, func(rec *PartitionRecord) {
		first := time.Unix(0, rec.FirstMs * 1e6)
		key := WindowKey{
			IP:     rec.IP,
			Window: first.Truncate(5 * time.Minute).Unix(),
		}
		stats, exists := m[key]
		if !exists {
			stats = NewIPStats()
			stats.IP = rec.IP
			m[key] = stats
		}
		a.updateStatsFromRecord(stats, rec, first)
	})
	return m
}

func (a *Aggregator) updateStatsFromRecord(stats *IPStats, rec *PartitionRecord, first time.Time) {
	if rec.IsOut {
		stats.FlowCount++
		stats.AddUniqueDstIP(rec.TargetIP)
		stats.AddUniqueDstPort(int(rec.Port))
		stats.AddOutboundDstPort(int(rec.Port))
		stats.TotalBytes += float64(rec.InBytes)
		stats.TotalPackets += float64(rec.InPackets)

		switch rec.Proto {
		case 6:
			stats.TCPCount++
		case 17:
			stats.UDPCount++
		case 1:
			stats.ICMPCount++
		}

		if (rec.TCPFlags & 1) != 0 && (rec.TCPFlags & (2|4|8)) == 0 {
			stats.SynOnlyCount++
		}
		if (rec.TCPFlags & 8) != 0 {
			stats.RstCount++
		}

		if rec.Port < 1024 {
			stats.WellKnownPortCount++
		}

		tKey := TargetKey{IP: rec.TargetIP, Port: int(rec.Port)}
		stats.AddTargetStartTime(tKey, first)

		if rec.LastMs > 0 {
			duration := float64(rec.LastMs - rec.FirstMs) / 1000.0
			if duration < 0 {
				duration = 0
			}
			stats.SumDurationSec += duration
		}
	} else {
		stats.AddInboundDstPort(int(rec.Port))
	}
}

func (a *Aggregator) AllIPStats() []*IPStats {
	var all []*IPStats
	for i := 0; i < numPartitions; i++ {
		m := a.aggregatePartition(i)
		for _, stats := range m {
			all = append(all, stats)
		}
	}
	return all
}

func (a *Aggregator) ExtractAndFlushBefore(window int64) []*IPStats {
	var flushed []*IPStats
	for i := 0; i < numPartitions; i++ {
		m := make(map[WindowKey]*IPStats)
		var active []PartitionRecord

		a.readPartition(i, func(rec *PartitionRecord) {
			first := time.Unix(0, rec.FirstMs * 1e6)
			win := first.Truncate(5 * time.Minute).Unix()
			if win < window {
				key := WindowKey{IP: rec.IP, Window: win}
				stats, exists := m[key]
				if !exists {
					stats = NewIPStats()
					stats.IP = rec.IP
					m[key] = stats
				}
				a.updateStatsFromRecord(stats, rec, first)
			} else {
				active = append(active, *rec)
			}
		})

		for _, stats := range m {
			flushed = append(flushed, stats)
		}

		a.rewritePartition(i, active)
	}
	return flushed
}

func (a *Aggregator) rewritePartition(pIdx int, records []PartitionRecord) {
	a.mutexes[pIdx].Lock()
	defer a.mutexes[pIdx].Unlock()

	a.files[pIdx].Close()

	path := filepath.Join(a.tempDir, fmt.Sprintf("part_%d.bin", pIdx))
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("failed to recreate partition file %s: %v", path, err)
	}
	a.files[pIdx] = f
	a.buffers[pIdx] = a.buffers[pIdx][:0]

	if len(records) == 0 {
		return
	}

	bufSize := len(records) * 46
	buf := make([]byte, bufSize)
	for i, r := range records {
		offset := i * 46
		binary.BigEndian.PutUint32(buf[offset:offset+4], r.IP)
		binary.BigEndian.PutUint32(buf[offset+4:offset+8], r.TargetIP)
		binary.BigEndian.PutUint64(buf[offset+8:offset+16], uint64(r.FirstMs))
		binary.BigEndian.PutUint64(buf[offset+16:offset+24], uint64(r.LastMs))
		binary.BigEndian.PutUint64(buf[offset+24:offset+32], uint64(r.InBytes))
		binary.BigEndian.PutUint64(buf[offset+32:offset+40], uint64(r.InPackets))
		binary.BigEndian.PutUint16(buf[offset+40:offset+42], r.Port)
		binary.BigEndian.PutUint16(buf[offset+42:offset+44], r.Proto)
		buf[offset+44] = r.TCPFlags
		if r.IsOut {
			buf[offset+45] = 1
		} else {
			buf[offset+45] = 0
		}
	}
	a.files[pIdx].Write(buf)
}

func (a *Aggregator) FlushAll() []*IPStats {
	var all []*IPStats
	for i := 0; i < numPartitions; i++ {
		m := a.aggregatePartition(i)
		for _, stats := range m {
			all = append(all, stats)
		}
	}
	a.Close()
	return all
}

func (a *Aggregator) NumActiveKeys() int {
	var count int
	for i := 0; i < numPartitions; i++ {
		m := a.aggregatePartition(i)
		count += len(m)
	}
	return count
}
