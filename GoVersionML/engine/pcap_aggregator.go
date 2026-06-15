package engine

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"sync"

	"goversion/models"
)

type BinaryPcapRecord struct {
	IP        uint32
	Timestamp float64
	Length    uint32
	Port      uint16
	Proto     uint16
	TTL       uint8
	TCPFlags  uint8
	IsOut     bool
}

type PcapAggregator struct {
	tempDir string
	files   [numPartitions]*os.File
	writers [numPartitions]*bufio.Writer
	mutexes [numPartitions]sync.Mutex
	closed  bool
}

func NewPcapAggregator() *PcapAggregator {
	dir, err := os.MkdirTemp("", "goversion_pcap_parts_*")
	if err != nil {
		log.Fatalf("failed to create temp dir for pcap aggregator: %v", err)
	}

	p := &PcapAggregator{
		tempDir: dir,
	}

	for i := 0; i < numPartitions; i++ {
		path := filepath.Join(dir, fmt.Sprintf("part_%d.bin", i))
		f, err := os.Create(path)
		if err != nil {
			log.Fatalf("failed to create partition file %s: %v", path, err)
		}
		p.files[i] = f
		p.writers[i] = bufio.NewWriterSize(f, 65536)
	}

	return p
}

func (p *PcapAggregator) Update(record models.PcapRecord) {
	flags := encodeTCPFlags(record.TCPFlags)

	if record.SrcIP != "" {
		if srcIP, ok := ParseIPv4(record.SrcIP); ok {
			r := BinaryPcapRecord{
				IP:        srcIP,
				Timestamp: record.Timestamp,
				Length:    uint32(record.Length),
				Port:      uint16(record.DstPort),
				Proto:     uint16(record.Proto),
				TTL:       uint8(record.TTL),
				TCPFlags:  flags,
				IsOut:     true,
			}
			p.writeToPartition(srcIP, &r)
		}
	}

	if record.DstIP != "" {
		if dstIP, ok := ParseIPv4(record.DstIP); ok {
			r := BinaryPcapRecord{
				IP:        dstIP,
				Timestamp: record.Timestamp,
				Length:    uint32(record.Length),
				Port:      uint16(record.SrcPort),
				Proto:     uint16(record.Proto),
				TTL:       uint8(record.TTL),
				TCPFlags:  flags,
				IsOut:     false,
			}
			p.writeToPartition(dstIP, &r)
		}
	}
}

func (p *PcapAggregator) writeToPartition(ip uint32, r *BinaryPcapRecord) {
	pIdx := int(ip % numPartitions)
	p.mutexes[pIdx].Lock()
	defer p.mutexes[pIdx].Unlock()

	if p.closed {
		return
	}

	var buf [23]byte
	binary.BigEndian.PutUint32(buf[0:4], r.IP)
	binary.BigEndian.PutUint64(buf[4:12], math.Float64bits(r.Timestamp))
	binary.BigEndian.PutUint32(buf[12:16], r.Length)
	binary.BigEndian.PutUint16(buf[16:18], r.Port)
	binary.BigEndian.PutUint16(buf[18:20], r.Proto)
	buf[20] = r.TTL
	buf[21] = r.TCPFlags
	if r.IsOut {
		buf[22] = 1
	} else {
		buf[22] = 0
	}

	p.writers[pIdx].Write(buf[:23])
}

func (p *PcapAggregator) Close() {
	if p.closed {
		return
	}
	p.closed = true
	for i := 0; i < numPartitions; i++ {
		if p.writers[i] != nil {
			p.writers[i].Flush()
		}
		if p.files[i] != nil {
			p.files[i].Close()
		}
	}
	if p.tempDir != "" {
		os.RemoveAll(p.tempDir)
		p.tempDir = ""
	}
}

func (p *PcapAggregator) readPartition(pIdx int, callback func(*BinaryPcapRecord)) error {
	p.mutexes[pIdx].Lock()
	p.writers[pIdx].Flush()
	p.files[pIdx].Sync()
	p.mutexes[pIdx].Unlock()

	f, err := os.Open(filepath.Join(p.tempDir, fmt.Sprintf("part_%d.bin", pIdx)))
	if err != nil {
		return err
	}
	defer f.Close()

	r := readerPool64k.Get().(*bufio.Reader)
	r.Reset(f)
	defer readerPool64k.Put(r)

	var buf [23]byte
	for {
		var rec BinaryPcapRecord
		_, err := io.ReadFull(r, buf[:])
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return err
		}

		rec.IP = binary.BigEndian.Uint32(buf[0:4])
		rec.Timestamp = math.Float64frombits(binary.BigEndian.Uint64(buf[4:12]))
		rec.Length = binary.BigEndian.Uint32(buf[12:16])
		rec.Port = binary.BigEndian.Uint16(buf[16:18])
		rec.Proto = binary.BigEndian.Uint16(buf[18:20])
		rec.TTL = buf[20]
		rec.TCPFlags = buf[21]
		rec.IsOut = buf[22] == 1

		callback(&rec)
	}
	return nil
}

func (p *PcapAggregator) aggregatePartition(pIdx int) map[WindowKey]*PcapIPStats {
	m := make(map[WindowKey]*PcapIPStats)
	p.readPartition(pIdx, func(rec *BinaryPcapRecord) {
		win := int64(rec.Timestamp) / 300 * 300
		key := WindowKey{
			IP:     rec.IP,
			Window: win,
		}
		stats, exists := m[key]
		if !exists {
			stats = NewPcapIPStats(rec.IP, win)
			m[key] = stats
		}

		// Recreate record logic
		prec := models.PcapRecord{
			Timestamp: rec.Timestamp,
			Length:    int(rec.Length),
			SrcPort:   int(rec.Port),
			DstPort:   int(rec.Port),
			Proto:     int(rec.Proto),
			TTL:       rec.TTL,
		}
		var flagBytes []byte
		if (rec.TCPFlags & 1) != 0 { flagBytes = append(flagBytes, 'S') }
		if (rec.TCPFlags & 2) != 0 { flagBytes = append(flagBytes, 'A') }
		if (rec.TCPFlags & 4) != 0 { flagBytes = append(flagBytes, 'F') }
		if (rec.TCPFlags & 8) != 0 { flagBytes = append(flagBytes, 'R') }
		if (rec.TCPFlags & 16) != 0 { flagBytes = append(flagBytes, 'P') }
		if (rec.TCPFlags & 32) != 0 { flagBytes = append(flagBytes, 'E') }
		if (rec.TCPFlags & 64) != 0 { flagBytes = append(flagBytes, 'C') }
		prec.TCPFlags = string(flagBytes)

		stats.Update(prec, rec.IsOut)
	})
	return m
}

func (p *PcapAggregator) AllIPStats() []*PcapIPStats {
	var all []*PcapIPStats
	for i := 0; i < numPartitions; i++ {
		m := p.aggregatePartition(i)
		for _, stats := range m {
			all = append(all, stats)
		}
	}
	return all
}

func (p *PcapAggregator) ExtractAndFlushBefore(window int64) []*PcapIPStats {
	var flushed []*PcapIPStats
	for i := 0; i < numPartitions; i++ {
		m := make(map[WindowKey]*PcapIPStats)
		var active []*BinaryPcapRecord

		p.readPartition(i, func(rec *BinaryPcapRecord) {
			win := int64(rec.Timestamp) / 300 * 300
			if win < window {
				key := WindowKey{IP: rec.IP, Window: win}
				stats, exists := m[key]
				if !exists {
					stats = NewPcapIPStats(rec.IP, win)
					m[key] = stats
				}

				prec := models.PcapRecord{
					Timestamp: rec.Timestamp,
					Length:    int(rec.Length),
					SrcPort:   int(rec.Port),
					DstPort:   int(rec.Port),
					Proto:     int(rec.Proto),
					TTL:       rec.TTL,
				}
				var flagBytes []byte
				if (rec.TCPFlags & 1) != 0 { flagBytes = append(flagBytes, 'S') }
				if (rec.TCPFlags & 2) != 0 { flagBytes = append(flagBytes, 'A') }
				if (rec.TCPFlags & 4) != 0 { flagBytes = append(flagBytes, 'F') }
				if (rec.TCPFlags & 8) != 0 { flagBytes = append(flagBytes, 'R') }
				if (rec.TCPFlags & 16) != 0 { flagBytes = append(flagBytes, 'P') }
				if (rec.TCPFlags & 32) != 0 { flagBytes = append(flagBytes, 'E') }
				if (rec.TCPFlags & 64) != 0 { flagBytes = append(flagBytes, 'C') }
				prec.TCPFlags = string(flagBytes)

				stats.Update(prec, rec.IsOut)
			} else {
				active = append(active, rec)
			}
		})

		for _, stats := range m {
			flushed = append(flushed, stats)
		}

		p.rewritePartition(i, active)
	}
	return flushed
}

func (p *PcapAggregator) rewritePartition(pIdx int, records []*BinaryPcapRecord) {
	p.mutexes[pIdx].Lock()
	defer p.mutexes[pIdx].Unlock()

	p.writers[pIdx].Flush()
	p.files[pIdx].Close()

	path := filepath.Join(p.tempDir, fmt.Sprintf("part_%d.bin", pIdx))
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("failed to recreate partition file %s: %v", path, err)
	}
	p.files[pIdx] = f
	p.writers[pIdx] = bufio.NewWriterSize(f, 65536)

	var buf [23]byte
	for _, r := range records {
		binary.BigEndian.PutUint32(buf[0:4], r.IP)
		binary.BigEndian.PutUint64(buf[4:12], math.Float64bits(r.Timestamp))
		binary.BigEndian.PutUint32(buf[12:16], r.Length)
		binary.BigEndian.PutUint16(buf[16:18], r.Port)
		binary.BigEndian.PutUint16(buf[18:20], r.Proto)
		buf[20] = r.TTL
		buf[21] = r.TCPFlags
		if r.IsOut {
			buf[22] = 1
		} else {
			buf[22] = 0
		}
		p.writers[pIdx].Write(buf[:23])
	}
	p.writers[pIdx].Flush()
}

func (p *PcapAggregator) FlushAll() []*PcapIPStats {
	var all []*PcapIPStats
	for i := 0; i < numPartitions; i++ {
		m := p.aggregatePartition(i)
		for _, stats := range m {
			all = append(all, stats)
		}
	}
	p.Close()
	return all
}

func (p *PcapAggregator) NumActiveKeys() int {
	var count int
	for i := 0; i < numPartitions; i++ {
		m := p.aggregatePartition(i)
		count += len(m)
	}
	return count
}
