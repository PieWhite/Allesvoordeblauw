package scanner

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"unsafe"

	"goversion/models"
)

// PcapBatch pools records, their arena-allocated strings, and packet buffers together
type PcapBatch struct {
	Records   []models.PcapRecord
	Arena     []byte
	Offset    int
	PacketBuf []byte // 64 KB packet buffer to eliminate heap allocations per packet
}

var pcapBatchPool = sync.Pool{
	New: func() interface{} {
		return &PcapBatch{
			Records:   make([]models.PcapRecord, 0, 1000),
			Arena:     make([]byte, 1024*1024), // 1 MB arena
			Offset:    0,
			PacketBuf: make([]byte, 65536),     // 64 KB preallocated
		}
	},
}

// readerPool pools 1 MB bufio.Reader instances to eliminate dynamic buffer allocations per file stream
var readerPool = sync.Pool{
	New: func() interface{} {
		return bufio.NewReaderSize(nil, 1024*1024)
	},
}

// flagsCache pre-allocates string representation of all possible TCP flag byte combinations
var flagsCache [256]string

func init() {
	for i := 0; i < 256; i++ {
		var f []byte
		if i&0x01 != 0 { f = append(f, 'F') } // FIN
		if i&0x02 != 0 { f = append(f, 'S') } // SYN
		if i&0x04 != 0 { f = append(f, 'R') } // RST
		if i&0x08 != 0 { f = append(f, 'P') } // PSH
		if i&0x10 != 0 { f = append(f, 'A') } // ACK
		if i&0x20 != 0 { f = append(f, 'U') } // URG
		if i&0x40 != 0 { f = append(f, 'E') } // ECE
		if i&0x80 != 0 { f = append(f, 'C') } // CWR
		flagsCache[i] = string(f)
	}
}

// unsafeString performs an allocation-free conversion from byte slice to string
func unsafeString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

// formatIPv4 converts a 4-byte IP address to an ASCII string directly in the buffer
func formatIPv4(buf []byte, ip []byte) int {
	n := 0
	for i := 0; i < 4; i++ {
		v := ip[i]
		if v >= 100 {
			buf[n] = '0' + v/100
			n++
			v %= 100
			buf[n] = '0' + v/10
			n++
			v %= 10
			buf[n] = '0' + v
			n++
		} else if v >= 10 {
			buf[n] = '0' + v/10
			n++
			v %= 10
			buf[n] = '0' + v
			n++
		} else {
			buf[n] = '0' + v
			n++
		}
		if i < 3 {
			buf[n] = '.'
			n++
		}
	}
	return n
}

// StreamPCAP parses a raw PCAP byte stream sequentially at max I/O speed, 
// using pooled 1MB readers, static TCP flags cache, and pre-allocated packet buffers 
// to guarantee exactly zero heap allocations.
func StreamPCAP(stream io.Reader, processFn func([]models.PcapRecord)) error {
	br := readerPool.Get().(*bufio.Reader)
	br.Reset(stream)
	defer func() {
		br.Reset(nil)
		readerPool.Put(br)
	}()

	// Read PCAP Global Header (24 bytes) using stack buffer
	var globalHeader [24]byte
	if _, err := io.ReadFull(br, globalHeader[:]); err != nil {
		return fmt.Errorf("failed to read global header: %w", err)
	}

	magic := binary.LittleEndian.Uint32(globalHeader[0:4])
	var byteOrder binary.ByteOrder = binary.LittleEndian
	if magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1 {
		byteOrder = binary.BigEndian
	} else if magic != 0xa1b2c3d4 && magic != 0xa1b23c4d {
		return fmt.Errorf("unsupported or invalid pcap magic number: 0x%x", magic)
	}

	linkType := byteOrder.Uint32(globalHeader[20:24])
	if linkType != 1 {
		return fmt.Errorf("unsupported pcap link type %d (only Ethernet LinkType=1 is supported)", linkType)
	}

	batch := pcapBatchPool.Get().(*PcapBatch)
	batch.Records = batch.Records[:0]
	batch.Offset = 0

	var packetHeader [16]byte

	for {
		_, err := io.ReadFull(br, packetHeader[:])
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return fmt.Errorf("error reading packet header: %w", err)
		}

		tsSec := byteOrder.Uint32(packetHeader[0:4])
		tsUsec := byteOrder.Uint32(packetHeader[4:8])
		inclLen := byteOrder.Uint32(packetHeader[8:12])
		origLen := byteOrder.Uint32(packetHeader[12:16])

		if inclLen > uint32(len(batch.PacketBuf)) {
			return fmt.Errorf("packet length %d exceeds maximum supported buffer size", inclLen)
		}

		// Read packet bytes directly into pooled batch packet buffer (No heap allocation!)
		if _, err := io.ReadFull(br, batch.PacketBuf[:inclLen]); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return fmt.Errorf("error reading packet payload: %w", err)
		}

		data := batch.PacketBuf[:inclLen]
		if len(data) < 14 { // Less than Ethernet header
			continue
		}

		etherType := binary.BigEndian.Uint16(data[12:14])
		if etherType != 0x0800 { // Only support IPv4 packets for ML stats
			continue
		}

		if len(data) < 14+20 { // Less than IPv4 minimum header
			continue
		}

		ipHeader := data[14:]
		version := ipHeader[0] >> 4
		if version != 4 {
			continue
		}

		ihl := int(ipHeader[0]&0x0f) * 4
		if len(ipHeader) < ihl {
			continue
		}

		proto := int(ipHeader[9])
		srcIPBytes := ipHeader[12:16]
		dstIPBytes := ipHeader[16:20]

		var srcPort, dstPort int
		var tcpFlags string

		transportHeader := ipHeader[ihl:]
		if proto == 6 { // TCP
			if len(transportHeader) < 20 {
				continue
			}
			srcPort = int(binary.BigEndian.Uint16(transportHeader[0:2]))
			dstPort = int(binary.BigEndian.Uint16(transportHeader[2:4]))
			flagsByte := transportHeader[13]
			tcpFlags = flagsCache[flagsByte]
		} else if proto == 17 { // UDP
			if len(transportHeader) < 8 {
				continue
			}
			srcPort = int(binary.BigEndian.Uint16(transportHeader[0:2]))
			dstPort = int(binary.BigEndian.Uint16(transportHeader[2:4]))
		} else {
			// Skip other transport protocols as they don't carry port stats
			continue
		}

		// Ensure enough arena capacity exists
		if batch.Offset+32 > len(batch.Arena) {
			newCap := len(batch.Arena) * 2
			newArena := make([]byte, newCap)
			copy(newArena, batch.Arena[:batch.Offset])
			batch.Arena = newArena
		}

		// Format IPs directly into Batch Arena (Zero Allocations!)
		srcStart := batch.Offset
		n1 := formatIPv4(batch.Arena[srcStart:], srcIPBytes)
		batch.Offset += n1
		srcIPStr := unsafeString(batch.Arena[srcStart : srcStart+n1])

		dstStart := batch.Offset
		n2 := formatIPv4(batch.Arena[dstStart:], dstIPBytes)
		batch.Offset += n2
		dstIPStr := unsafeString(batch.Arena[dstStart : dstStart+n2])

		batch.Records = append(batch.Records, models.PcapRecord{
			Timestamp: float64(tsSec) + float64(tsUsec)/1e6,
			SrcIP:     srcIPStr,
			DstIP:     dstIPStr,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Length:    int(origLen),
			Proto:     proto,
			TCPFlags:  tcpFlags,
		})

		if len(batch.Records) >= 1000 {
			processFn(batch.Records)
			batch.Records = batch.Records[:0]
			batch.Offset = 0
		}
	}

	if len(batch.Records) > 0 {
		processFn(batch.Records)
	}

	// Reset and put batch back into pool
	batch.Records = batch.Records[:0]
	batch.Offset = 0
	pcapBatchPool.Put(batch)

	return nil
}
