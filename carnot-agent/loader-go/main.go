package main

// This is a minimal, memory-safe userspace loader for the OpenSSL uprobes eBPF program.
// It uses cilium/ebpf to attach uprobes/uretprobes to libssl.so.3 and reads events from a ring buffer.
// NOTE: This is a skeleton; it assumes your BPF object defines:
//   - map: handshake_events (BPF_MAP_TYPE_RINGBUF)
//   - prog: uprobe handlers for SSL_set_tlsext_host_name, SSL_CTX_set_ciphersuites, SSL_CTX_set1_groups_list
//   - prog: uretprobe handler for SSL_do_handshake
//
// Build: go build ./
// Run : sudo ./loader-go -lib /lib/x86_64-linux-gnu/libssl.so.3 -obj ../ebpf-core/openssl_handshake.bpf.o
//
import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// BPF event shape (keep in sync with openssl_handshake.bpf.c)
type rawEvent struct {
	TsNs    uint64
	Pid     uint32
	Tid     uint32
	SslPtr  uint64
	EvtType uint8
	Success uint8
	Payload [128]byte
	_       [6]byte // padding from alignment (struct size multiple of 8)
}

const (
	evtSNISet        = 1
	evtGroupsSet     = 2
	evtHandshakeRet  = 3
	stateTTL         = 2 * time.Second
	expireInterval   = 500 * time.Millisecond
)

type partialState struct {
	SNI       string
	Groups    []string
	T0        time.Time
	LastMerge time.Time
}

type key struct {
	Pid    uint32
	Tid    uint32
	SslPtr uint64
}

type observation struct {
	Source               string    `json:"source"`
	AssetID              *string   `json:"asset_id"`
	Owner                *string   `json:"owner"`
	DataClass            *string   `json:"data_class"`
	SecrecyLifetimeYears *int      `json:"secrecy_lifetime_years"`
	Exposure             *string   `json:"exposure"`
	SNI                  string    `json:"sni"`
	GroupsOffered        []string  `json:"groups_offered"`
	HandshakeSuccess     bool      `json:"handshake_success"`
	Pid                  uint32    `json:"pid"`
	Tid                  uint32    `json:"tid"`
	SslPtr               string    `json:"ssl_ptr"`
	Time                 time.Time `json:"time"`
	Confidence           float32   `json:"confidence"`
}

func main() {
	var libPath string
	var objPath string
	var outPath string
	flag.StringVar(&libPath, "lib", "/lib/x86_64-linux-gnu/libssl.so.3", "Path to libssl.so.3")
	flag.StringVar(&objPath, "obj", "../ebpf-core/openssl_handshake.bpf.o", "Path to eBPF object file")
	flag.StringVar(&outPath, "out", "", "Output JSONL file for runtime observations")
	flag.Parse()

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("new collection: %v", err)
	}
	defer coll.Close()

	// Attach uprobes
	var links []link.Link
	attach := func(sym string, progName string, ret bool) {
		prog, ok := coll.Programs[progName]
		if !ok {
			log.Fatalf("program %s not found in object", progName)
		}
		var l link.Link
		var err error
		if ret {
			l, err = link.OpenUretprobe(0, libPath, sym, prog, nil)
		} else {
			l, err = link.OpenUprobe(0, libPath, sym, prog, nil)
		}
		if err != nil {
			log.Fatalf("attach %s (%s): %v", sym, progName, err)
		}
		links = append(links, l)
		log.Printf("attached %s -> %s", sym, progName)
	}
	// These names must match section names in your .bpf.c (CO-RE uprobe/uretprobe sections)
	attach("SSL_set_tlsext_host_name", "uprobe_ssl_set_sni", false)
	attach("SSL_CTX_set_ciphersuites", "uprobe_ssl_ctx_set_ciphersuites", false)
	attach("SSL_CTX_set1_groups_list", "uprobe_ssl_ctx_set1_groups_list", false)
	attach("SSL_do_handshake", "uretprobe_ssl_do_handshake", true)

	rbMap, ok := coll.Maps["handshake_events"]
	if !ok {
		log.Fatalf("handshake_events ringbuf map not found in object")
	}
	rd, err := ringbuf.NewReader(rbMap)
	if err != nil {
		log.Fatalf("open ringbuf: %v", err)
	}
	defer rd.Close()

	var outFile *os.File
	if outPath != "" {
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			log.Fatalf("mkdir out: %v", err)
		}
		outFile, err = os.OpenFile(outPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatalf("open out file: %v", err)
		}
		defer outFile.Close()
	}

	// Correlation state
	states := make(map[key]*partialState)
	var mu sync.Mutex
	var totalEvents, dropped uint64

	// Expiration goroutine
	go func() {
		ticker := time.NewTicker(expireInterval)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			mu.Lock()
			for k, st := range states {
				if now.Sub(st.T0) > stateTTL {
					delete(states, k)
				}
			}
			mu.Unlock()
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	log.Println("reading events & correlating... (Ctrl+C to stop)")
	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("ringbuf read: %v", err)
				continue
			}
			totalEvents++
			var raw rawEvent
			if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
				log.Printf("decode: %v", err)
				continue
			}
			// Extract payload string
			pay := string(bytes.TrimRight(raw.Payload[:], "\x00"))
			k := key{Pid: raw.Pid, Tid: raw.Tid, SslPtr: raw.SslPtr}
			ts := time.Unix(0, int64(raw.TsNs)).UTC()
			mu.Lock()
			st, ok := states[k]
			if !ok {
				st = &partialState{T0: ts, LastMerge: ts}
				states[k] = st
			}
			switch raw.EvtType {
			case evtSNISet:
				if st.SNI == "" {
					st.SNI = pay
				}
				st.LastMerge = ts
			case evtGroupsSet:
				if pay != "" {
					st.Groups = dedupeAppend(st.Groups, splitCSV(pay))
				}
				st.LastMerge = ts
			case evtHandshakeRet:
				// finalize observation
				obs := observation{
					Source:           "runtime.ebpf",
					SNI:              st.SNI,
					GroupsOffered:    st.Groups,
					HandshakeSuccess: raw.Success == 1,
					Pid:              raw.Pid,
					Tid:              raw.Tid,
					SslPtr:           fmt.Sprintf("0x%x", raw.SslPtr),
					Time:             ts,
					Confidence:       0.8,
				}
				delete(states, k)
				mu.Unlock()
				// Emit JSON
				line, err := json.Marshal(obs)
				if err != nil {
					log.Printf("marshal obs: %v", err)
					continue
				}
				if outFile != nil {
					if _, err := outFile.Write(append(line, '\n')); err != nil {
						log.Printf("write out: %v", err)
					}
				} else {
					fmt.Println(string(line))
				}
				continue
			default:
				// unknown event
			}
			mu.Unlock()
		}
	}()
		}
	}()

	<-stop
	for _, l := range links {
		l.Close()
	}
	// Stats: ringbuf records lost
	var info ebpf.MapInfo
	if rbMap != nil {
		if err := rbMap.Info(&info); err == nil {
			// ringbuf map doesn't expose drops directly; rely on reader stats (since v0.12 ringbuf Reader has LostSamples())
			if ls, err := readerLostSamples(rd); err == nil {
				dropped = ls
			}
		}
	}
	lossPct := 0.0
	if totalEvents > 0 {
		lossPct = float64(dropped) / float64(totalEvents+dropped) * 100
	}
	log.Printf("stopped. events_total=%d dropped=%d loss_pct=%.2f%%", totalEvents, dropped, lossPct)
}

// helper: split comma/space separated list into slice
func splitCSV(s string) []string {
	var out []string
	field := bytes.Buffer{}
	flush := func() {
		if field.Len() == 0 { return }
		out = append(out, field.String())
		field.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case ',', ' ', '\t', '\n':
			flush()
		default:
			field.WriteByte(c)
		}
	}
	flush()
	return out
}

func dedupeAppend(dst, src []string) []string {
	if len(src) == 0 { return dst }
	seen := make(map[string]struct{}, len(dst))
	for _, d := range dst { seen[d] = struct{}{} }
	for _, s := range src {
		if s == "" { continue }
		if _, ok := seen[s]; ok { continue }
		dst = append(dst, s)
		seen[s] = struct{}{}
	}
	return dst
}

// Access lost samples (not exported pre 0.13). Use reflection fallback; harmless if fails.
func readerLostSamples(r *ringbuf.Reader) (uint64, error) {
	type ls interface { LostSamples() uint64 }
	if v, ok := any(r).(ls); ok {
		return v.LostSamples(), nil
	}
	return 0, errors.New("lost samples unsupported")
}
