// -------------------------------------------------------------------------------
// vault-cert-manager - Aggregator Dashboard
//
// Centralized dashboard that discovers all vault-cert-manager instances via
// Consul and displays their certificate status in a unified view.
// -------------------------------------------------------------------------------

package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"
)

// ConsulService represents a service instance from Consul.
type ConsulService struct {
	Node           string `json:"Node"`
	Address        string `json:"Address"`
	ServiceAddress string `json:"ServiceAddress"`
	ServicePort    int    `json:"ServicePort"`
}

// NodeStatus represents the status of all certs on a single node.
type NodeStatus struct {
	Node    string       `json:"node"`
	Address string       `json:"address"`
	Certs   []CertStatus `json:"certs"`
	Error   string       `json:"error,omitempty"`
}

// Aggregator provides a centralized dashboard for all vault-cert-manager instances.
type Aggregator struct {
	consulAddr  string
	serviceName string
	templates   *template.Template
	httpClient  *http.Client
}

// NewAggregator creates a new aggregator dashboard.
func NewAggregator(consulAddr, serviceName string) *Aggregator {
	tmpl := template.Must(template.New("").Funcs(template.FuncMap{
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return "Never"
			}
			return t.Format("2006-01-02 15:04:05")
		},
	}).ParseFS(templateFS, "templates/*.html"))

	return &Aggregator{
		consulAddr:  consulAddr,
		serviceName: serviceName,
		templates:   tmpl,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// RegisterHandlers registers the aggregator HTTP handlers.
func (a *Aggregator) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/", a.handleDashboard)
	mux.HandleFunc("/api/status", a.handleAPIStatus)
	mux.HandleFunc("/api/rotate/", a.handleAPIRotate)
}

// discoverServices queries Consul for all vault-cert-manager instances.
func (a *Aggregator) discoverServices() ([]ConsulService, error) {
	url := fmt.Sprintf("%s/v1/catalog/service/%s", a.consulAddr, a.serviceName)

	resp, err := a.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to query Consul: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("consul returned status %d: %s", resp.StatusCode, string(body))
	}

	var services []ConsulService
	if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
		return nil, fmt.Errorf("failed to decode Consul response: %w", err)
	}

	return services, nil
}

// fetchNodeStatus queries a single node's status endpoint.
func (a *Aggregator) fetchNodeStatus(svc ConsulService) NodeStatus {
	addr := svc.ServiceAddress
	if addr == "" {
		addr = svc.Address
	}

	url := fmt.Sprintf("http://%s:%d/api/status", addr, svc.ServicePort)

	status := NodeStatus{
		Node:    svc.Node,
		Address: fmt.Sprintf("%s:%d", addr, svc.ServicePort),
	}

	resp, err := a.httpClient.Get(url)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		status.Error = fmt.Sprintf("status %d: %s", resp.StatusCode, string(body))
		return status
	}

	if err := json.NewDecoder(resp.Body).Decode(&status.Certs); err != nil {
		status.Error = fmt.Sprintf("decode error: %v", err)
		return status
	}

	return status
}

// fetchAllStatuses queries all discovered nodes in parallel.
func (a *Aggregator) fetchAllStatuses() ([]NodeStatus, error) {
	services, err := a.discoverServices()
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	results := make([]NodeStatus, len(services))

	for i, svc := range services {
		wg.Add(1)
		go func(idx int, s ConsulService) {
			defer wg.Done()
			results[idx] = a.fetchNodeStatus(s)
		}(i, svc)
	}

	wg.Wait()

	// Sort by node name
	sort.Slice(results, func(i, j int) bool {
		return results[i].Node < results[j].Node
	})

	return results, nil
}

// handleDashboard serves the aggregated dashboard page.
func (a *Aggregator) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	statuses, err := a.fetchAllStatuses()
	if err != nil {
		slog.Error("Failed to fetch statuses", "error", err)
		http.Error(w, "Failed to fetch node statuses: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Nodes []NodeStatus
	}{
		Nodes: statuses,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.templates.ExecuteTemplate(w, "aggregator.html", data); err != nil {
		slog.Error("Failed to render dashboard", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleAPIStatus returns aggregated status as JSON.
func (a *Aggregator) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	statuses, err := a.fetchAllStatuses()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(statuses)
}

// handleAPIRotate proxies rotate requests to the appropriate node.
// Path format: /api/rotate/{node}/{certName} or /api/rotate/{node}/all
func (a *Aggregator) handleAPIRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse path: /api/rotate/{node}/{cert}
	path := r.URL.Path[len("/api/rotate/"):]
	var nodeName, certName string

	for i, c := range path {
		if c == '/' {
			nodeName = path[:i]
			certName = path[i+1:]
			break
		}
	}

	if nodeName == "" {
		http.Error(w, "Node name required: /api/rotate/{node}/{cert}", http.StatusBadRequest)
		return
	}
	if certName == "" {
		certName = "all"
	}

	// Find the node
	services, err := a.discoverServices()
	if err != nil {
		http.Error(w, "Failed to discover services: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var targetSvc *ConsulService
	for _, svc := range services {
		if svc.Node == nodeName {
			targetSvc = &svc
			break
		}
	}

	if targetSvc == nil {
		http.Error(w, "Node not found: "+nodeName, http.StatusNotFound)
		return
	}

	// Proxy the request
	addr := targetSvc.ServiceAddress
	if addr == "" {
		addr = targetSvc.Address
	}

	var targetURL string
	if certName == "all" {
		targetURL = fmt.Sprintf("http://%s:%d/api/rotate/all", addr, targetSvc.ServicePort)
	} else {
		targetURL = fmt.Sprintf("http://%s:%d/api/rotate/%s", addr, targetSvc.ServicePort, certName)
	}

	slog.Info("Proxying rotate request", "node", nodeName, "cert", certName, "url", targetURL)

	proxyReq, err := http.NewRequest(http.MethodPost, targetURL, nil)
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := a.httpClient.Do(proxyReq)
	if err != nil {
		http.Error(w, "Failed to proxy request: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Forward response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// StartServer starts the aggregator HTTP server.
func (a *Aggregator) StartServer(port int) error {
	mux := http.NewServeMux()
	a.RegisterHandlers(mux)

	addr := fmt.Sprintf(":%d", port)
	slog.Info("Starting aggregator dashboard", "address", addr, "consul", a.consulAddr, "service", a.serviceName)

	return http.ListenAndServe(addr, mux)
}
