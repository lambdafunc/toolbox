//go:build !windows

package main

import (
    "bufio"
    "bytes"
    "context"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "net"
    "os"
    "os/exec"
    "regexp"
    "runtime"
    "sort"
    "strings"
    "sync"
    "time"
)

var defaultPorts = []int{22, 80, 443, 53, 139, 445, 548, 631, 5353, 8000, 8080, 8443, 3389, 5432, 5900, 1883, 3306, 9100, 32400, 27017, 5000, 21, 23, 25}
var defaultProbePorts = []int{22, 80, 443, 53, 445, 139, 5353}

type row struct {
    IP           string  `json:"ip"`
    Hostname     string  `json:"hostname"`
    MAC          string  `json:"mac"`
    OpenTCPPorts []int   `json:"open_tcp_ports"`
}

type arpEntry struct {
    name string
    mac  string
}

func parsePorts(input string) ([]int, error) {
    if input == "" {
        return append([]int{}, defaultPorts...), nil
    }
    set := map[int]struct{}{}
    parts := strings.Split(input, ",")
    for _, part := range parts {
        part = strings.TrimSpace(part)
        if part == "" {
            continue
        }
        if strings.Contains(part, "-") {
            ab := strings.SplitN(part, "-", 2)
            var a, b int
            fmt.Sscanf(ab[0], "%d", &a)
            fmt.Sscanf(ab[1], "%d", &b)
            if a > b {
                a, b = b, a
            }
            for p := a; p <= b; p++ {
                if p >= 1 && p <= 65535 {
                    set[p] = struct{}{}
                }
            }
        } else {
            var p int
            fmt.Sscanf(part, "%d", &p)
            if p >= 1 && p <= 65535 {
                set[p] = struct{}{}
            }
        }
    }
    out := make([]int, 0, len(set))
    for p := range set {
        out = append(out, p)
    }
    sort.Ints(out)
    return out, nil
}

func normalizePrefix(subnet string) (string, error) {
    subnet = strings.TrimSpace(subnet)
    if strings.HasSuffix(subnet, "/24") {
        base := strings.Split(subnet, "/")[0]
        parts := strings.Split(base, ".")
        if len(parts) != 4 {
            return "", fmt.Errorf("invalid subnet: %s", subnet)
        }
        return strings.Join(parts[:3], ".") + ".", nil
    }
    if strings.HasSuffix(subnet, ".") {
        parts := strings.Split(subnet, ".")
        if len(parts) != 4 {
            return "", fmt.Errorf("invalid prefix: %s", subnet)
        }
        return subnet, nil
    }
    parts := strings.Split(subnet, ".")
    if len(parts) == 4 {
        return strings.Join(parts[:3], ".") + ".", nil
    }
    return "", fmt.Errorf("unsupported subnet format: %s", subnet)
}

func autodetectPrefix() string {
    // Parse ifconfig output for first private IPv4
    out, err := exec.Command("ifconfig").Output()
    if err != nil {
        return ""
    }
    re := regexp.MustCompile(`\binet\s+(\d+\.\d+\.\d+\.\d+)\b`)
    matches := re.FindAllStringSubmatch(string(out), -1)
    for _, m := range matches {
        ip := m[1]
        if strings.HasPrefix(ip, "127.") {
            continue
        }
        if isPrivateIPv4(ip) {
            parts := strings.Split(ip, ".")
            if len(parts) == 4 {
                return strings.Join(parts[:3], ".") + "."
            }
        }
    }
    return ""
}

func isPrivateIPv4(ip string) bool {
    if strings.HasPrefix(ip, "10.") {
        return true
    }
    if strings.HasPrefix(ip, "192.168.") {
        return true
    }
    // 172.16.0.0 – 172.31.255.255
    if strings.HasPrefix(ip, "172.") {
        parts := strings.Split(ip, ".")
        if len(parts) >= 2 {
            var a int
            fmt.Sscanf(parts[1], "%d", &a)
            if a >= 16 && a <= 31 {
                return true
            }
        }
    }
    return false
}

func pingOne(ip string, timeout time.Duration) bool {
    var cmd *exec.Cmd
    if runtime.GOOS == "darwin" {
        cmd = exec.Command("ping", "-n", "-c", "1", "-t", "64", ip)
    } else {
        // Linux iputils ping
        w := int(timeout.Seconds())
        if w < 1 {
            w = 1
        }
        cmd = exec.Command("ping", "-n", "-c", "1", "-W", fmt.Sprintf("%d", w), ip)
    }
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr

    done := make(chan error, 1)
    go func() { done <- cmd.Run() }()
    select {
    case err := <-done:
        return err == nil && cmd.ProcessState.Success()
    case <-time.After(timeout + 200*time.Millisecond):
        _ = cmd.Process.Kill()
        return false
    }
}

func reverseDNS(ip string, timeout time.Duration) string {
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    names, err := net.DefaultResolver.LookupAddr(ctx, ip)
    if err != nil || len(names) == 0 {
        return "-"
    }
    name := strings.TrimSuffix(names[0], ".")
    return name
}

func arpMAC(ip string) string {
    out, err := exec.Command("arp", "-n", ip).Output()
    if err == nil {
        // macOS: ? (192.168.0.10) at a1:b2:c3:d4:e5:f6 on en0
        re := regexp.MustCompile(`\bat\s+([0-9a-f:]{11,})\b`)
        if m := re.FindStringSubmatch(string(out)); len(m) == 2 {
            return m[1]
        }
    }
    out, err = exec.Command("arp", "-a").Output()
    if err == nil {
        // hostname (192.168.0.10) at a1:b2:c3:d4:e5:f6 on en0
        re := regexp.MustCompile(regexp.QuoteMeta("("+ip+")") + `\s+at\s+([0-9a-f:]{11,})`)
        if m := re.FindStringSubmatch(string(out)); len(m) == 2 {
            return m[1]
        }
    }
    return "-"
}

func loadArpCache() map[string]arpEntry {
    cache := make(map[string]arpEntry)
    out, err := exec.Command("arp", "-a").Output()
    if err != nil {
        return cache
    }
    // Lines like: hostname (192.168.0.10) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
    scanner := bufio.NewScanner(bytes.NewReader(out))
    re := regexp.MustCompile(`^([^?].*?)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{11,})`)
    re2 := regexp.MustCompile(`^\?\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{11,})`)
    for scanner.Scan() {
        line := scanner.Text()
        if m := re.FindStringSubmatch(line); len(m) == 4 {
            name := strings.TrimSpace(m[1])
            ip := m[2]
            mac := m[3]
            cache[ip] = arpEntry{name: name, mac: mac}
            continue
        }
        if m := re2.FindStringSubmatch(line); len(m) == 3 {
            ip := m[1]
            mac := m[2]
            if ent, ok := cache[ip]; ok {
                ent.mac = mac
                cache[ip] = ent
            } else {
                cache[ip] = arpEntry{name: "", mac: mac}
            }
        }
    }
    return cache
}

func avahiResolve(ip string, timeout time.Duration) string {
    if _, err := exec.LookPath("avahi-resolve-address"); err != nil {
        return ""
    }
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    cmd := exec.CommandContext(ctx, "avahi-resolve-address", "-4", ip)
    out, err := cmd.Output()
    if err != nil || len(out) == 0 {
        return ""
    }
    // Format: 192.168.0.10 hostname.local
    fields := strings.Fields(string(out))
    if len(fields) >= 2 {
        return strings.TrimSuffix(fields[1], ".")
    }
    return ""
}

func nmbLookup(ip string, timeout time.Duration) string {
    if _, err := exec.LookPath("nmblookup"); err != nil {
        return ""
    }
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    cmd := exec.CommandContext(ctx, "nmblookup", "-A", ip)
    out, err := cmd.Output()
    if err != nil || len(out) == 0 {
        return ""
    }
    // Parse lines; choose first unique <00> ACTIVE that is not __MSBROWSE__ and not a GROUP
    scanner := bufio.NewScanner(bytes.NewReader(out))
    re := regexp.MustCompile(`^([A-Z0-9_-]{1,15})\s+<00>\s+`)
    for scanner.Scan() {
        line := scanner.Text()
        if strings.Contains(line, "GROUP") || strings.Contains(line, "__MSBROWSE__") {
            continue
        }
        if m := re.FindStringSubmatch(line); len(m) == 2 {
            return m[1]
        }
    }
    return ""
}

func resolveHostname(ip string, timeout time.Duration, arp map[string]arpEntry) string {
    // Order: reverse DNS -> Avahi/mDNS -> NetBIOS -> ARP name
    if name := reverseDNS(ip, timeout); name != "-" && name != "" {
        return name
    }
    if name := avahiResolve(ip, timeout); name != "" {
        return name
    }
    if name := nmbLookup(ip, timeout); name != "" {
        return name
    }
    if ent, ok := arp[ip]; ok && ent.name != "" && ent.name != "?" {
        return ent.name
    }
    return "-"
}

func dialTCP(ip string, port int, timeout time.Duration) (open bool, refused bool) {
    d := net.Dialer{Timeout: timeout}
    conn, err := d.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
    if err != nil {
        if opErr := new(net.OpError); errors.As(err, &opErr) {
            // Consider connection refused as host reachable
            if strings.Contains(strings.ToLower(err.Error()), "refused") {
                return false, true
            }
        }
        return false, false
    }
    _ = conn.Close()
    return true, true
}

func uniqueSorted[T ~string](in []T) []T {
    set := map[T]struct{}{}
    for _, v := range in {
        set[v] = struct{}{}
    }
    out := make([]T, 0, len(set))
    for v := range set {
        out = append(out, v)
    }
    sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
    return out
}

func main() {
    subnet := flag.String("subnet", "192.168.0.0/24", "Subnet /24 or prefix like 192.168.0.")
    auto := flag.Bool("auto", false, "Auto-detect local /24 prefix")
    portsStr := flag.String("ports", "", "Comma ports or ranges (e.g., 22,80,443 or 1-1024)")
    timeout := flag.Float64("timeout", 0.8, "Timeout seconds for ping/connect")
    hostConc := flag.Int("host-concurrency", 256, "Concurrent hosts during discovery")
    connConc := flag.Int("conn-concurrency", 1024, "Concurrent TCP connections during port scan")
    discovery := flag.String("discovery", "ping", "Discovery method: ping|tcp")
    output := flag.String("output", "text", "Output: text|csv|json")
    ssh := flag.Bool("ssh", false, "Print SSH suggestions for port 22")
    includeUnresp := flag.Bool("include-unresponsive", false, "Include IPs without response")
    flag.Parse()

    prefix := ""
    if *auto && (*subnet == "" || *subnet == "192.168.0.0/24") {
        prefix = autodetectPrefix()
        if prefix == "" {
            prefix = "192.168.0."
        }
    } else {
        var err error
        prefix, err = normalizePrefix(*subnet)
        if err != nil {
            fmt.Fprintln(os.Stderr, err)
            os.Exit(1)
        }
    }

    ports, err := parsePorts(*portsStr)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    tmo := time.Duration(*timeout * float64(time.Second))

    fmt.Printf("[+] Discovering hosts on %s0/24 via %s\n", prefix, *discovery)

    // Build targets
    targets := make([]string, 0, 254)
    for i := 1; i <= 254; i++ {
        targets = append(targets, fmt.Sprintf("%s%d", prefix, i))
    }

    aliveMu := sync.Mutex{}
    alive := make([]string, 0, 32)

    if *discovery == "ping" {
        sem := make(chan struct{}, *hostConc)
        wg := sync.WaitGroup{}
        for _, ip := range targets {
            sem <- struct{}{}
            wg.Add(1)
            ip := ip
            go func() {
                defer wg.Done()
                ok := pingOne(ip, tmo)
                if ok {
                    aliveMu.Lock()
                    alive = append(alive, ip)
                    aliveMu.Unlock()
                }
                <-sem
            }()
        }
        wg.Wait()
        sort.Slice(alive, func(i, j int) bool { return ipLess(alive[i], alive[j]) })
    } else { // tcp discovery
        sem := make(chan struct{}, *connConc)
        wg := sync.WaitGroup{}
        aliveSet := sync.Map{}
        for _, ip := range targets {
            for _, p := range defaultProbePorts {
                sem <- struct{}{}
                wg.Add(1)
                ip := ip
                p := p
                go func() {
                    defer wg.Done()
                    open, refused := dialTCP(ip, p, tmo)
                    if open || refused {
                        aliveSet.Store(ip, struct{}{})
                    }
                    <-sem
                }()
            }
        }
        wg.Wait()
        alive = make([]string, 0, 32)
        aliveSet.Range(func(key, value any) bool {
            alive = append(alive, key.(string))
            return true
        })
        sort.Slice(alive, func(i, j int) bool { return ipLess(alive[i], alive[j]) })
    }

    fmt.Printf("[+] Live hosts found: %d\n", len(alive))
    if len(alive) == 0 && !*includeUnresp {
        fmt.Println("[+] Done")
        return
    }

    scanIPs := targets
    if !*includeUnresp {
        scanIPs = alive
    }
    fmt.Printf("[+] Scanning TCP ports (%d ports) with concurrency=%d, timeout=%.1fs\n", len(ports), *connConc, *timeout)

    openMap := make(map[string][]int)
    sem := make(chan struct{}, *connConc)
    wg := sync.WaitGroup{}
    for _, ip := range scanIPs {
        for _, p := range ports {
            sem <- struct{}{}
            wg.Add(1)
            ip := ip
            p := p
            go func() {
                defer wg.Done()
                open, _ := dialTCP(ip, p, tmo)
                if open {
                    // Append safely
                    aliveMu.Lock()
                    openMap[ip] = append(openMap[ip], p)
                    aliveMu.Unlock()
                }
                <-sem
            }()
        }
    }
    wg.Wait()

    // Load ARP cache once for names+MACs
    arpCache := loadArpCache()

    rows := make([]row, 0, len(scanIPs))
    for _, ip := range scanIPs {
        ports := openMap[ip]
        sort.Ints(ports)
        name := resolveHostname(ip, 700*time.Millisecond, arpCache)
        mac := "-"
        if ent, ok := arpCache[ip]; ok && ent.mac != "" {
            mac = ent.mac
        } else {
            mac = arpMAC(ip)
        }
        rows = append(rows, row{IP: ip, Hostname: name, MAC: mac, OpenTCPPorts: ports})
    }

    sort.Slice(rows, func(i, j int) bool { return ipLess(rows[i].IP, rows[j].IP) })
    switch *output {
    case "csv":
        fmt.Println("IP,Hostname,MAC,OpenTCPPorts")
        for _, r := range rows {
            portsStr := intsCSV(r.OpenTCPPorts)
            name := strings.ReplaceAll(r.Hostname, "\"", "\"\"")
            fmt.Printf("\"%s\",\"%s\",\"%s\",\"%s\"\n", r.IP, name, r.MAC, portsStr)
        }
    case "json":
        enc := json.NewEncoder(os.Stdout)
        enc.SetIndent("", "  ")
        _ = enc.Encode(rows)
    default:
        fmt.Printf("%-15s  %-32s  %-17s  %s\n", "IP", "Hostname", "MAC", "Open TCP Ports")
        for _, r := range rows {
            fmt.Printf("%-15s  %-32s  %-17s  %s\n", r.IP, r.Hostname, r.MAC, intsCSV(r.OpenTCPPorts))
        }
    }

    if *ssh {
        fmt.Println("\n[SSH suggestions]")
        for _, r := range rows {
            if containsInt(r.OpenTCPPorts, 22) {
                label := r.Hostname
                if label == "-" {
                    label = r.IP
                }
                fmt.Printf("ssh %s  # %s\n", r.IP, label)
            }
        }
    }

    fmt.Println("[+] Done")
}

func ipLess(a, b string) bool {
    // compare dotted decimal strings by numeric value
    ap := strings.Split(a, ".")
    bp := strings.Split(b, ".")
    for i := 0; i < 4; i++ {
        var ai, bi int
        fmt.Sscanf(ap[i], "%d", &ai)
        fmt.Sscanf(bp[i], "%d", &bi)
        if ai != bi {
            return ai < bi
        }
    }
    return false
}

func intsCSV(v []int) string {
    if len(v) == 0 {
        return ""
    }
    sb := strings.Builder{}
    for i, n := range v {
        if i > 0 {
            sb.WriteByte(',')
        }
        sb.WriteString(fmt.Sprintf("%d", n))
    }
    return sb.String()
}

func containsInt(v []int, needle int) bool {
    for _, n := range v {
        if n == needle {
            return true
        }
    }
    return false
}
