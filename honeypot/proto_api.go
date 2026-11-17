package main

// HTTP-APIs, die Angreifer gezielt suchen. Alle laufen über serveHTTP (proto_http.go) und
// unterscheiden sich nur in Kopfzeilen, Antworten und darin, was als "Befehl" zählt:
//   - dockerapi:     Docker Engine API (Container anlegen, exec, Images ziehen)
//   - ollama:        Ollama / OpenAI-kompatible KI-Schnittstelle (Port 11434): Modelle
//                    stehlen, Rechenzeit nutzen, Prompts ausprobieren
//   - elasticsearch: Elasticsearch 7 (Port 9200): Daten suchen, Skript-Lücken
//   - kubernetes:    Kubernetes-API-Server (6443) und Kubelet (10250), mit oder ohne TLS
//
// Antworten sind statisch und klein; nichts wird ausgeführt oder gespeichert.

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type httpAPI struct {
	headers func(*Session) string              // zusätzliche Kopfzeilen (mit \r\n)
	command func(*http.Request, []byte) string // was als Befehl aufgezeichnet wird ("" = nichts)
	respond func(*Session, *http.Request) (int, string, string, map[string]string)
}

var dockerAPI = &httpAPI{
	headers: func(s *Session) string {
		return "Server: Docker/" + s.m.prof().DockerVer + " (linux)\r\nApi-Version: 1.43\r\nOstype: linux\r\n"
	},
	command: dockerCommand,
	respond: dockerResponse,
}

const jsonUTF8 = "application/json; charset=utf-8"

func cmdText(s string) string { return printable([]byte(s), budgetCommand) }

// ---------- Ollama ----------

func handleOllama(s *Session) { serveHTTP(s, ollamaAPI) }

var ollamaAPI = &httpAPI{command: ollamaCommand, respond: ollamaResponse}

var ollamaModels = []struct{ Name, Family, Size string }{
	{"llama3.1:8b", "llama", "8.0B"}, {"qwen2.5-coder:7b", "qwen2", "7.6B"}, {"nomic-embed-text:latest", "nomic-bert", "137M"},
}

func ollamaCommand(req *http.Request, body []byte) string {
	if req.Method != "POST" && req.Method != "DELETE" {
		return ""
	}
	var b struct {
		Model, Name, Prompt, Source, Destination string
		Messages                                 []struct{ Role, Content string }
	}
	json.Unmarshal(body, &b)
	model := b.Model
	if model == "" {
		model = b.Name
	}
	last := b.Prompt
	if n := len(b.Messages); last == "" && n > 0 {
		last = b.Messages[n-1].Content
	}
	switch p := req.URL.Path; p {
	case "/api/generate", "/api/chat", "/v1/chat/completions", "/v1/completions":
		return cmdText("prompt " + model + ": " + last)
	case "/api/pull", "/api/push", "/api/delete", "/api/create", "/api/show":
		return cmdText(strings.TrimPrefix(p, "/api/") + " " + model)
	case "/api/copy":
		return cmdText("copy " + b.Source + " " + b.Destination)
	case "/api/embed", "/api/embeddings", "/v1/embeddings":
		return cmdText("embed " + model)
	}
	return cmdText(req.Method + " " + req.URL.RequestURI())
}

const ollamaReply = "Hello! How can I help you today?"

func ollamaResponse(s *Session, req *http.Request) (int, string, string, map[string]string) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	model := ollamaModels[0].Name
	switch p := req.URL.Path; {
	case p == "/" || p == "":
		return 200, "text/plain; charset=utf-8", "Ollama is running", nil
	case p == "/api/version":
		return 200, jsonUTF8, `{"version":"0.12.6"}`, nil
	case p == "/api/tags":
		var list []map[string]any
		for _, m := range ollamaModels {
			list = append(list, map[string]any{"name": m.Name, "model": m.Name, "modified_at": "2026-09-14T18:02:11.4729Z", "size": int64(4920753328),
				"digest": randHex(32), "details": map[string]any{"format": "gguf", "family": m.Family, "parameter_size": m.Size, "quantization_level": "Q4_K_M"}})
		}
		return 200, jsonUTF8, mustJSON(map[string]any{"models": list}), nil
	case p == "/api/ps":
		return 200, jsonUTF8, `{"models":[]}`, nil
	case p == "/api/show" && req.Method == "POST":
		return 200, jsonUTF8, mustJSON(map[string]any{"modelfile": "FROM " + model, "parameters": "stop \"<|eot_id|>\"",
			"details": map[string]any{"format": "gguf", "family": "llama", "parameter_size": "8.0B", "quantization_level": "Q4_K_M"}}), nil
	case p == "/api/generate" && req.Method == "POST":
		return 200, jsonUTF8, mustJSON(map[string]any{"model": model, "created_at": now, "response": ollamaReply, "done": true, "done_reason": "stop",
			"total_duration": 912345678, "eval_count": 9}), nil
	case p == "/api/chat" && req.Method == "POST":
		return 200, jsonUTF8, mustJSON(map[string]any{"model": model, "created_at": now, "message": map[string]string{"role": "assistant", "content": ollamaReply},
			"done": true, "done_reason": "stop"}), nil
	case (p == "/api/pull" || p == "/api/push" || p == "/api/create" || p == "/api/copy") && req.Method == "POST":
		return 200, jsonUTF8, `{"status":"success"}`, nil
	case p == "/api/delete" && req.Method == "DELETE":
		return 200, jsonUTF8, "", nil
	case p == "/v1/models":
		var list []map[string]any
		for _, m := range ollamaModels {
			list = append(list, map[string]any{"id": m.Name, "object": "model", "created": 1757872931, "owned_by": "library"})
		}
		return 200, jsonUTF8, mustJSON(map[string]any{"object": "list", "data": list}), nil
	case p == "/v1/chat/completions" && req.Method == "POST":
		return 200, jsonUTF8, mustJSON(map[string]any{"id": "chatcmpl-" + randHex(3), "object": "chat.completion", "created": time.Now().Unix(), "model": model,
			"choices": []any{map[string]any{"index": 0, "message": map[string]string{"role": "assistant", "content": ollamaReply}, "finish_reason": "stop"}}}), nil
	}
	return 404, "text/plain; charset=utf-8", "404 page not found", nil
}

// ---------- Elasticsearch ----------

func handleElastic(s *Session) { serveHTTP(s, elasticAPI) }

var elasticAPI = &httpAPI{
	headers: func(*Session) string { return "X-elastic-product: Elasticsearch\r\n" },
	command: elasticCommand,
	respond: elasticResponse,
}

func elasticCommand(req *http.Request, body []byte) string {
	p := req.URL.Path
	if req.Method == "GET" || req.Method == "HEAD" {
		// Suchen mit Skript im Query-String (alte RCE-Lücken) zählen als Befehl
		if strings.Contains(req.URL.RawQuery, "script") || strings.Contains(req.URL.RawQuery, "source=") {
			return cmdText(req.Method + " " + req.URL.RequestURI())
		}
		return ""
	}
	out := req.Method + " " + p
	if len(body) > 0 {
		out += " " + string(body)
	}
	return cmdText(out)
}

var elasticIndices = []struct{ Name, Docs, Size string }{
	{"customers", "48211", "21.4mb"}, {"orders-2026", "193877", "88.1mb"}, {"logs-app", "1204551", "412.7mb"},
}

func elasticResponse(s *Session, req *http.Request) (int, string, string, map[string]string) {
	p := strings.TrimSuffix(req.URL.Path, "/")
	switch {
	case p == "":
		return 200, jsonUTF8, mustJSON(map[string]any{"name": s.m.Hostname(), "cluster_name": "elasticsearch", "cluster_uuid": "Tq3v" + randHex(9),
			"version": map[string]any{"number": "7.17.9", "build_flavor": "default", "build_type": "docker", "build_hash": "ef48222227ee6b9e70e502f0f0daa52435ee634d",
				"build_date": "2023-01-31T05:34:43.305517834Z", "build_snapshot": false, "lucene_version": "8.11.1",
				"minimum_wire_compatibility_version": "6.8.0", "minimum_index_compatibility_version": "6.0.0-beta1"},
			"tagline": "You Know, for Search"}), nil
	case p == "/_cat/indices":
		if req.URL.Query().Get("format") == "json" {
			var list []map[string]string
			for _, ix := range elasticIndices {
				list = append(list, map[string]string{"health": "yellow", "status": "open", "index": ix.Name, "pri": "1", "rep": "1", "docs.count": ix.Docs, "store.size": ix.Size})
			}
			return 200, jsonUTF8, mustJSON(list), nil
		}
		var b strings.Builder
		for _, ix := range elasticIndices {
			b.WriteString("yellow open " + ix.Name + " " + randHex(11) + " 1 1 " + ix.Docs + " 0 " + ix.Size + " " + ix.Size + "\n")
		}
		return 200, "text/plain; charset=UTF-8", b.String(), nil
	case p == "/_cluster/health":
		return 200, jsonUTF8, `{"cluster_name":"elasticsearch","status":"yellow","timed_out":false,"number_of_nodes":1,"number_of_data_nodes":1,"active_primary_shards":3,"active_shards":3,"unassigned_shards":3}`, nil
	case p == "/_nodes" || strings.HasPrefix(p, "/_nodes/"):
		return 200, jsonUTF8, mustJSON(map[string]any{"_nodes": map[string]int{"total": 1, "successful": 1, "failed": 0}, "cluster_name": "elasticsearch",
			"nodes": map[string]any{randHex(11): map[string]any{"name": s.m.Hostname(), "version": "7.17.9", "roles": []string{"data", "ingest", "master"}}}}), nil
	case strings.HasSuffix(p, "/_search") || p == "/_search" || strings.HasSuffix(p, "/_count"):
		if strings.HasSuffix(p, "/_count") {
			return 200, jsonUTF8, `{"count":0,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0}}`, nil
		}
		return 200, jsonUTF8, `{"took":2,"timed_out":false,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0},"hits":{"total":{"value":0,"relation":"eq"},"max_score":null,"hits":[]}}`, nil
	case req.Method == "PUT" || req.Method == "POST":
		return 201, jsonUTF8, `{"_index":"` + jsonSafe(strings.Trim(strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)[0], " ")) + `","_id":"` + randHex(10) + `","_version":1,"result":"created","_shards":{"total":2,"successful":1,"failed":0}}`, nil
	case req.Method == "DELETE":
		return 200, jsonUTF8, `{"acknowledged":true}`, nil
	}
	ix := jsonSafe(strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)[0])
	return 404, jsonUTF8, `{"error":{"root_cause":[{"type":"index_not_found_exception","reason":"no such index [` + ix + `]","index":"` + ix + `"}],"type":"index_not_found_exception","reason":"no such index [` + ix + `]","index":"` + ix + `"},"status":404}`, nil
}

// jsonSafe kürzt und maskiert einen Text für die Einbettung in eine JSON-Zeichenkette.
func jsonSafe(s string) string {
	b, _ := json.Marshal(clip(s, 128))
	return strings.Trim(string(b), `"`)
}

// ---------- Kubernetes (API-Server und Kubelet) ----------

// handleKubernetes spricht TLS, wenn der Client damit beginnt, sonst Klartext-HTTP.
func handleKubernetes(s *Session) {
	if s.Mode == "tarpit" {
		httpTarpit(s)
		return
	}
	br := bufio.NewReader(s.Conn)
	s.ReadDeadline(30 * time.Second)
	if b, err := br.Peek(1); err == nil && b[0] == 0x16 {
		if !upgradeTLS(s, br) {
			return
		}
	} else {
		s.Conn = &readerConn{Conn: s.Conn, r: br}
	}
	serveHTTP(s, k8sAPI)
}

var k8sAPI = &httpAPI{
	headers: func(*Session) string {
		return "Audit-Id: " + uuidLike() + "\r\nCache-Control: no-cache, private\r\n"
	},
	command: k8sCommand,
	respond: k8sResponse,
}

func uuidLike() string {
	h := randHex(16)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func k8sCommand(req *http.Request, body []byte) string {
	p := req.URL.Path
	q := req.URL.Query()
	// exec/attach (API-Server und Kubelet): Befehl steht im Query-String
	if cmds := q["command"]; len(cmds) > 0 && (strings.Contains(p, "/exec") || strings.Contains(p, "/attach")) {
		return cmdText("exec " + p + ": " + strings.Join(cmds, " "))
	}
	if req.Method == "GET" || req.Method == "HEAD" {
		return ""
	}
	// Kubelet /run/<ns>/<pod>/<container>: Befehl im Formular "cmd"
	if strings.HasPrefix(p, "/run/") {
		v, _ := url.ParseQuery(string(body))
		c := v.Get("cmd")
		if c == "" {
			c = q.Get("cmd")
		}
		return cmdText("run " + strings.TrimPrefix(p, "/run/") + ": " + c)
	}
	if strings.HasSuffix(p, "/pods") && req.Method == "POST" {
		var pod struct {
			Spec struct {
				HostPID, HostNetwork bool
				Containers           []struct {
					Image           string
					Command, Args   []string
					SecurityContext struct{ Privileged bool }
				}
				Volumes []struct{ HostPath *struct{ Path string } }
			}
		}
		json.Unmarshal(body, &pod)
		parts := []string{"create pod"}
		for _, c := range pod.Spec.Containers {
			parts = append(parts, "image="+c.Image)
			if len(c.Command)+len(c.Args) > 0 {
				parts = append(parts, "cmd="+strings.Join(append(c.Command, c.Args...), " "))
			}
			if c.SecurityContext.Privileged {
				parts = append(parts, "privileged")
			}
		}
		for _, v := range pod.Spec.Volumes {
			if v.HostPath != nil {
				parts = append(parts, "binds="+v.HostPath.Path+":")
			}
		}
		if pod.Spec.HostPID {
			parts = append(parts, "--pid=host")
		}
		return cmdText(strings.Join(parts, " "))
	}
	out := req.Method + " " + p
	if len(body) > 0 {
		out += " " + string(body)
	}
	return cmdText(out)
}

func k8sPodList() string {
	pods := []struct{ NS, Name, Image string }{
		{"default", "web-7d9f8c6b5-x2kqp", "nginx:1.25"}, {"default", "api-5f6c9d8f7-r8tzn", "registry.local/api:2.3.1"},
		{"kube-system", "coredns-5dd5756b68-9lw4h", "registry.k8s.io/coredns/coredns:v1.10.1"},
	}
	var items []map[string]any
	for _, p := range pods {
		items = append(items, map[string]any{
			"metadata": map[string]any{"name": p.Name, "namespace": p.NS, "uid": uuidLike(), "creationTimestamp": "2026-10-02T08:14:31Z"},
			"spec":     map[string]any{"containers": []any{map[string]any{"name": strings.SplitN(p.Name, "-", 2)[0], "image": p.Image}}, "nodeName": "node-1"},
			"status":   map[string]any{"phase": "Running", "podIP": "10.244.0." + p.Name[len(p.Name)-1:]},
		})
	}
	return mustJSON(map[string]any{"kind": "PodList", "apiVersion": "v1", "metadata": map[string]string{"resourceVersion": "481920"}, "items": items})
}

func k8sResponse(s *Session, req *http.Request) (int, string, string, map[string]string) {
	p := strings.TrimSuffix(req.URL.Path, "/")
	switch {
	case p == "/version":
		return 200, "application/json", `{"major":"1","minor":"28","gitVersion":"v1.28.4","gitCommit":"bae2c62678db2b5053817bc97181fcc2e8388103","gitTreeState":"clean","buildDate":"2023-11-15T16:48:54Z","goVersion":"go1.20.11","compiler":"gc","platform":"linux/amd64"}`, nil
	case p == "/healthz" || p == "/livez" || p == "/readyz":
		return 200, "text/plain; charset=utf-8", "ok", nil
	case p == "/api":
		return 200, "application/json", `{"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[{"clientCIDR":"0.0.0.0/0","serverAddress":"10.0.0.11:6443"}]}`, nil
	case p == "/api/v1/namespaces":
		return 200, "application/json", `{"kind":"NamespaceList","apiVersion":"v1","items":[{"metadata":{"name":"default"}},{"metadata":{"name":"kube-system"}},{"metadata":{"name":"monitoring"}}]}`, nil
	case p == "/pods" || p == "/runningpods" || p == "/api/v1/pods" || (strings.HasPrefix(p, "/api/v1/namespaces/") && strings.HasSuffix(p, "/pods") && req.Method == "GET"):
		return 200, "application/json", k8sPodList(), nil
	case strings.HasSuffix(p, "/pods") && req.Method == "POST":
		return 201, "application/json", `{"kind":"Pod","apiVersion":"v1","metadata":{"name":"pod-` + randHex(3) + `","namespace":"default","uid":"` + uuidLike() + `"},"status":{"phase":"Pending"}}`, nil
	case strings.HasSuffix(p, "/secrets") || strings.HasSuffix(p, "/configmaps"):
		kind := "SecretList"
		if strings.HasSuffix(p, "/configmaps") {
			kind = "ConfigMapList"
		}
		return 200, "application/json", `{"kind":"` + kind + `","apiVersion":"v1","metadata":{"resourceVersion":"481920"},"items":[]}`, nil
	case strings.HasPrefix(p, "/run/"):
		return 200, "text/plain; charset=utf-8", "", nil
	case p == "/metrics" || p == "/stats/summary" || p == "/spec":
		return 200, "text/plain; charset=utf-8", "# HELP kubelet_running_pods Number of pods running\n# TYPE kubelet_running_pods gauge\nkubelet_running_pods 3\n", nil
	}
	return 403, "application/json", `{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User \"system:anonymous\" cannot get path \"` + jsonSafe(req.URL.Path) + `\"","reason":"Forbidden","details":{},"code":403}`, nil
}
