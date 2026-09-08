// 测试用后端：把收到的请求原样回显，用来验证反代有没有正确转发。
//
//	go run ./backend -port 9001 -name 服务A
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	port := flag.Int("port", 9001, "监听端口")
	name := flag.String("name", "backend", "服务名")
	flag.Parse()

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// 回显所有 X- 开头的头，方便验证认证模块有没有正确注入身份信息
		custom := map[string]string{}
		for k := range r.Header {
			upper := strings.ToUpper(k)
			if strings.HasPrefix(upper, "X-") {
				custom[upper] = r.Header.Get(k)
			}
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"service":           *name,
			"backend_port":      *port,
			"method":            r.Method,
			"path":              r.URL.Path,
			"query":             r.URL.RawQuery,
			"host_header":       r.Host,
			"x_forwarded_for":   r.Header.Get("X-Forwarded-For"),
			"x_real_ip":         r.Header.Get("X-Real-IP"),
			"x_forwarded_host":  r.Header.Get("X-Forwarded-Host"),
			"x_forwarded_proto": r.Header.Get("X-Forwarded-Proto"),
			"custom_headers":    custom,
		})
	})

	// 分块输出，用来验证 SSE / 流式响应不被缓冲
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for i := 0; i < 3; i++ {
			fmt.Fprintf(w, "chunk %d from %s\n", i, *name)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(300 * time.Millisecond)
		}
	})

	log.Printf("后端 %s 启动于 %s", *name, addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
