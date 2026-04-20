package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	timeout     = 1 * time.Second // 超时时间
	maxDuration = 2 * time.Second // 最大持续时间
	udpIdleTimeout = 30 * time.Second // UDP 会话空闲超时
)

var (
	activeConnections  int32 // 用于跟踪活跃连接的数量
	validIPClientCache sync.Map
	randomMu           sync.Mutex
	randomGenerator    = rand.New(rand.NewSource(time.Now().UnixNano()))
)

// IPManager 用于安全管理 IP 地址状态
type IPManager struct {
	mu            sync.RWMutex
	currentIP     string
	ipAddresses   []string
	currentIndex  int
	allIPsChecked bool
}

func NewIPManager() *IPManager {
	return &IPManager{}
}

func (m *IPManager) SetIPAddresses(ips []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipAddresses = ips
	m.currentIndex = 0
	m.allIPsChecked = false
}

func (m *IPManager) GetCurrentIP() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentIP
}

func (m *IPManager) SetCurrentIP(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentIP = ip
}

func (m *IPManager) GetIPAddresses() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ipAddresses
}

func (m *IPManager) IsAllIPsChecked() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.allIPsChecked
}

func (m *IPManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipAddresses = []string{}
	m.currentIP = ""
	m.currentIndex = 0
	m.allIPsChecked = false
}

func (m *IPManager) switchToNextValidIP(useTLS bool, port int, domain string, code int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := m.currentIndex + 1; i < len(m.ipAddresses); i++ {
		ip := m.ipAddresses[i]

		if ip == m.currentIP {
			continue
		}

		if checkValidIP(ip, port, useTLS, domain, code) {
			m.currentIP = ip
			m.currentIndex = i
			m.allIPsChecked = false
			log.Printf("切换到新的有效 IP: %s 更新 IP 索引: %d", m.currentIP, m.currentIndex)
			return true
		}
	}

	m.allIPsChecked = true
	log.Println("所有 IP 都已检查过，程序将退出")
	return false
}

type result struct {
	ip          string        
	dataCenter  string        
	region      string        
	city        string        
	latency     string        
	tcpDuration time.Duration 
}

type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

func main() {
	localAddr := flag.String("addr", "0.0.0.0:1234", "本地监听的 IP 和端口")
	code := flag.Int("code", 200, "HTTP/HTTPS 响应状态码")
	coloFilter := flag.String("colo", "", "筛选数据中心例如 HKG,SJC,LAX")
	Delay := flag.Int("delay", 300, "有效延迟（毫秒）")
	domain := flag.String("domain", "cloudflaremirrors.com/debian", "响应状态码检查的域名地址")
	ipCount := flag.Int("ipnum", 20, "提取的有效IP数量")
	ipsType := flag.String("ips", "4", "指定生成IPv4还是IPv6地址 (4或6)")
	num := flag.Int("num", 5, "目标负载 IP 数量")
	port := flag.Int("port", 443, "转发的目标端口")
	random := flag.Bool("random", true, "是否随机生成IP")
	maxThreads := flag.Int("task", 100, "并发请求最大协程数")
	useTLS := flag.Bool("tls", true, "是否为 TLS 端口")

	flag.Parse()

	ipManager := NewIPManager()

	// 启动 TCP 监听
	tcpListener, err := net.Listen("tcp", *localAddr)
	if err != nil {
		log.Fatalf("无法监听 TCP %s: %v", *localAddr, err)
	}
	defer tcpListener.Close()

	// 启动 UDP 监听
	udpAddr, err := net.ResolveUDPAddr("udp", *localAddr)
	if err != nil {
		log.Fatalf("解析 UDP 地址失败: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("无法监听 UDP %s: %v", *localAddr, err)
	}
	defer udpConn.Close()

	log.Printf("正在监听 %s (TCP/UDP) 并转发到 %d 个目标地址，有效延迟：%d ms", *localAddr, *num, *Delay)

	for {
		startTime := time.Now()
		locations, err := loadLocations()
		if err != nil {
			log.Printf("加载位置信息失败: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}

		locationMap := make(map[string]location)
		for _, loc := range locations {
			locationMap[loc.Iata] = loc
		}

		var url string
		var filename string
		switch *ipsType {
		case "6":
			filename = "ips-v6.txt"
			url = "https://www.baipiao.eu.org/cloudflare/ips-v6"
		case "4":
			filename = "ips-v4.txt"
			url = "https://www.baipiao.eu.org/cloudflare/ips-v4"
		default:
			fmt.Println("无效的IP类型")
			return
		}

		var content string
		if _, err = os.Stat(filename); os.IsNotExist(err) {
			content, err = getURLContent(url)
			if err != nil { return }
			saveToFile(filename, content)
		} else {
			content, err = getFileContent(filename)
			if err != nil { return }
		}

		var ipList []string
		if *random {
			ipList = parseIPList(content)
			if *ipsType == "6" { ipList = getRandomIPv6s(ipList) } else { ipList = getRandomIPv4s(ipList) }
		} else {
			ipList, _ = readIPs(filename)
		}

		results := scanIPs(ipList, locationMap, *maxThreads)
		if len(results) == 0 {
			time.Sleep(3 * time.Second)
			continue
		}

		if *coloFilter != "" {
			filters := strings.Split(*coloFilter, ",")
			var filteredResults []result
			for _, r := range results {
				for _, filter := range filters {
					if strings.EqualFold(r.dataCenter, filter) {
						filteredResults = append(filteredResults, r)
						break
					}
				}
			}
			results = filteredResults
		}

		sort.Slice(results, func(i, j int) bool { return results[i].tcpDuration < results[j].tcpDuration })
		if len(results) > *ipCount { results = results[:*ipCount] }

		for _, r := range results {
			fmt.Printf("%s | %s | %s | %s | %s\n", r.ip, r.dataCenter, r.region, r.city, r.latency)
		}

		var ips []string
		for _, r := range results { ips = append(ips, r.ip) }
		ipManager.SetIPAddresses(ips)

		currentIP := selectValidIP(ipManager, *useTLS, *port, *domain, *code)
		if currentIP == "" { continue }
		ipManager.SetCurrentIP(currentIP)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan bool)
		var loopWG sync.WaitGroup
		loopWG.Add(3)

		// 1. 状态检查线程
		go func() {
			defer loopWG.Done()
			statusCheck(ctx, *localAddr, *useTLS, *port, done, *domain, *code, time.Duration(*Delay)*time.Millisecond, ipManager)
		}()

		// 2. TCP 转发线程
		go func() {
			defer loopWG.Done()
			for {
				select {
				case <-ctx.Done(): return
				default:
					tcpListener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
					conn, err := tcpListener.Accept()
					if err != nil { continue }
					atomic.AddInt32(&activeConnections, 1)
					currIP := ipManager.GetCurrentIP()
					go handleConnection(conn, generateTargets(currIP, *port, *num), time.Duration(*Delay)*time.Millisecond)
				}
			}
		}()

		// 3. UDP (H3) 转发线程
		go func() {
			defer loopWG.Done()
			handleUDPProxy(ctx, udpConn, ipManager, *port)
		}()

		<-done
		cancel()
		loopWG.Wait()
		ipManager.Clear()
		validIPClientCache = sync.Map{}
	}
}

// handleUDPProxy 处理 UDP 数据包转发 (H3 支持)
func handleUDPProxy(ctx context.Context, listenConn *net.UDPConn, ipManager *IPManager, targetPort int) {
	sessions := make(map[string]*net.UDPConn)
	var mu sync.Mutex
	buf := make([]byte, 65535)

	for {
		select {
		case <-ctx.Done():
			mu.Lock()
			for _, conn := range sessions { conn.Close() }
			mu.Unlock()
			return
		default:
			listenConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, clientAddr, err := listenConn.ReadFromUDP(buf)
			if err != nil { continue }

			clientKey := clientAddr.String()
			mu.Lock()
			targetConn, exists := sessions[clientKey]
			if !exists {
				currIP := ipManager.GetCurrentIP()
				targetAddrStr := currIP
				if strings.Contains(currIP, ":") { targetAddrStr = "[" + currIP + "]" }
				
				tAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", targetAddrStr, targetPort))
				tConn, err := net.DialUDP("udp", nil, tAddr)
				if err != nil {
					mu.Unlock()
					continue
				}
				targetConn = tConn
				sessions[clientKey] = targetConn
				
				// 启动后端回传协程
				go func(cAddr *net.UDPAddr, tc *net.UDPConn, key string) {
					defer func() {
						mu.Lock()
						delete(sessions, key)
						mu.Unlock()
						tc.Close()
					}()
					backBuf := make([]byte, 65535)
					for {
						tc.SetReadDeadline(time.Now().Add(udpIdleTimeout))
						bn, _, err := tc.ReadFromUDP(backBuf)
						if err != nil { return }
						listenConn.WriteToUDP(backBuf[:bn], cAddr)
					}
				}(clientAddr, targetConn, clientKey)
			}
			mu.Unlock()
			targetConn.Write(buf[:n])
		}
	}
}

// ---------------------------------------------------------
// 以下为原程序功能函数，保持逻辑不变
// ---------------------------------------------------------

func loadLocations() ([]location, error) {
	var locations []location
	if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
		resp, err := http.Get("https://www.baipiao.eu.org/cloudflare/locations")
		if err != nil { return nil, err }
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		json.Unmarshal(body, &locations)
		os.WriteFile("locations.json", body, 0644)
	} else {
		body, _ := os.ReadFile("locations.json")
		json.Unmarshal(body, &locations)
	}
	return locations, nil
}

func scanIPs(ipList []string, locationMap map[string]location, maxThreads int) []result {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []result
	thread := make(chan struct{}, maxThreads)
	var count int32
	total := len(ipList)

	for _, ip := range ipList {
		wg.Add(1)
		thread <- struct{}{}
		go func(ipAddr string) {
			defer func() {
				<-thread
				wg.Done()
				atomic.AddInt32(&count, 1)
			}()
			dialer := &net.Dialer{Timeout: timeout}
			start := time.Now()
			conn, err := dialer.Dial("tcp", net.JoinHostPort(ipAddr, "80"))
			if err != nil { return }
			defer conn.Close()
			tcpDuration := time.Since(start)

			req, _ := http.NewRequest("GET", "http://"+net.JoinHostPort(ipAddr, "80"), nil)
			req.Header.Set("User-Agent", "Mozilla/5.0")
			conn.SetDeadline(time.Now().Add(maxDuration))
			req.Write(conn)
			resp, err := http.ReadResponse(bufio.NewReader(conn), req)
			if err != nil { return }
			defer resp.Body.Close()

			cfRay := resp.Header.Get("CF-RAY")
			parts := strings.Split(cfRay, "-")
			if len(parts) < 2 { return }
			dataCenter := strings.TrimSpace(parts[len(parts)-1])
			
			loc, ok := locationMap[dataCenter]
			mu.Lock()
			if ok {
				results = append(results, result{ipAddr, dataCenter, loc.Region, loc.City, fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), tcpDuration})
			} else {
				results = append(results, result{ipAddr, dataCenter, "", "", fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), tcpDuration})
			}
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return results
}

func getURLContent(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil { return "", err }
	defer resp.Body.Close()
	var content strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() { content.WriteString(scanner.Text() + "\n") }
	return content.String(), nil
}

func getFileContent(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	return string(data), err
}

func saveToFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

func parseIPList(content string) []string {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var ipList []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" { ipList = append(ipList, line) }
	}
	return ipList
}

func nextRandomIntn(n int) int {
	randomMu.Lock()
	defer randomMu.Unlock()
	return randomGenerator.Intn(n)
}

func getRandomIPv4s(ipList []string) []string {
	var randomIPs []string
	for _, subnet := range ipList {
		subnet = strings.TrimSpace(subnet)
		if !strings.Contains(subnet, "/24") { continue }
		octets := strings.Split(strings.TrimSuffix(subnet, "/24"), ".")
		if len(octets) >= 4 {
			octets[3] = fmt.Sprintf("%d", nextRandomIntn(256))
			randomIPs = append(randomIPs, strings.Join(octets, "."))
		}
	}
	return randomIPs
}

func getRandomIPv6s(ipList []string) []string {
	var randomIPs []string
	for _, subnet := range ipList {
		subnet = strings.TrimSpace(subnet)
		baseIP := strings.TrimSuffix(subnet, "/48")
		sections := strings.Split(baseIP, ":")
		if len(sections) >= 3 {
			sections = sections[:3]
			for i := 3; i < 8; i++ { sections = append(sections, fmt.Sprintf("%x", nextRandomIntn(65536))) }
			randomIPs = append(randomIPs, strings.Join(sections, ":"))
		}
	}
	return randomIPs
}

func readIPs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil { return nil, err }
	defer file.Close()
	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" { continue }
		if strings.Contains(line, "/") {
			ipAddr, ipNet, _ := net.ParseCIDR(line)
			for currentIP := ipAddr.Mask(ipNet.Mask); ipNet.Contains(currentIP); incrementIP(currentIP) {
				ips = append(ips, currentIP.String())
			}
		} else { ips = append(ips, line) }
	}
	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 { break }
	}
}

func generateTargets(ip string, port int, num int) []string {
	targets := make([]string, num)
	address := ip
	if strings.Contains(ip, ":") { address = "[" + ip + "]" }
	for i := 0; i < num; i++ { targets[i] = fmt.Sprintf("%s:%d", address, port) }
	return targets
}

func checkValidIP(ip string, port int, useTLS bool, domain string, code int) bool {
	address := ip
	if strings.Contains(ip, ":") { address = "[" + ip + "]" }
	targetURL := fmt.Sprintf("http://%s", domain)
	if useTLS { targetURL = fmt.Sprintf("https://%s", domain) }

	cacheKey := fmt.Sprintf("%s:%d", address, port)
	clientAny, loaded := validIPClientCache.Load(cacheKey)
	var client *http.Client
	if loaded {
		client = clientAny.(*http.Client)
	} else {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, fmt.Sprintf("%s:%d", address, port))
			},
		}
		client = &http.Client{Timeout: 2 * time.Second, Transport: transport}
		validIPClientCache.Store(cacheKey, client)
	}

	resp, err := client.Get(targetURL)
	if err != nil { return false }
	defer resp.Body.Close()
	return resp.StatusCode == code
}

func selectValidIP(ipManager *IPManager, useTLS bool, port int, domain string, code int) string {
	for _, ip := range ipManager.GetIPAddresses() {
		if checkValidIP(ip, port, useTLS, domain, code) { return ip }
	}
	return ""
}

func statusCheck(ctx context.Context, localAddr string, useTLS bool, port int, done chan bool, domain string, code int, delay time.Duration, ipManager *IPManager) {
	_, localPort, _ := net.SplitHostPort(localAddr)
	checkAddr := "127.0.0.1:" + localPort
	for {
		select {
		case <-ctx.Done(): return
		default:
			failCount := 0
			for failCount < 2 {
				select {
				case <-ctx.Done(): return
				default:
					conn, err := net.DialTimeout("tcp", checkAddr, delay)
					if err != nil {
						failCount++
						time.Sleep(1 * time.Second)
						continue
					}
					conn.Close()
					failCount = 0
					time.Sleep(2 * time.Second)
					break
				}
			}
			if failCount >= 2 {
				if !ipManager.switchToNextValidIP(useTLS, port, domain, code) {
					done <- true
					return
				}
			}
		}
	}
}

func handleConnection(conn net.Conn, forwardAddrs []string, delay time.Duration) {
	defer func() {
		atomic.AddInt32(&activeConnections, -1)
		conn.Close()
	}()

	type connResult struct {
		conn  net.Conn
		delay time.Duration
	}
	results := make(chan connResult, len(forwardAddrs))

	for _, addr := range forwardAddrs {
		go func(targetAddr string) {
			start := time.Now()
			fConn, err := net.DialTimeout("tcp", targetAddr, delay)
			if err != nil {
				results <- connResult{nil, 0}
				return
			}
			results <- connResult{fConn, time.Since(start)}
		}(addr)
	}

	var bestConn net.Conn
	var bestDelay time.Duration
	for i := 0; i < len(forwardAddrs); i++ {
		res := <-results
		if res.conn != nil {
			if bestConn == nil || res.delay < bestDelay {
				if bestConn != nil { bestConn.Close() }
				bestConn = res.conn
				bestDelay = res.delay
			} else { res.conn.Close() }
		}
	}

	if bestConn != nil {
		pipeConnections(conn, bestConn)
	}
}

func pipeConnections(src, dst net.Conn) {
	var wg sync.WaitGroup
	var closeOnce sync.Once
	closeBoth := func() { closeOnce.Do(func() { src.Close(); dst.Close() }) }
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(src, dst); closeBoth() }()
	go func() { defer wg.Done(); io.Copy(dst, src); closeBoth() }()
	wg.Wait()
}