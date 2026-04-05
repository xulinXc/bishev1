package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"

	"bishe/internal/mcp"
)

type AIGenPythonFromExpBatchReq struct {
	Provider      string    `json:"provider"`
	APIKey        string    `json:"apiKey"`
	BaseURL       string    `json:"baseUrl"`
	Model         string    `json:"model"`
	TargetBaseURL string    `json:"targetBaseUrl"`
	TimeoutMs     int       `json:"timeoutMs"`
	ExpDir        string    `json:"expDir"`
	ExpPaths      []string  `json:"expPaths"`
	InlineExps    []ExpSpec `json:"inlineExps"`
	Concurrency   int       `json:"concurrency"`
}

func aiGenPythonFromExpBatchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AIGenPythonFromExpBatchReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	req.TargetBaseURL = strings.TrimSpace(req.TargetBaseURL)

	var exps []ExpSpec
	var err error
	if len(req.InlineExps) > 0 {
		exps = req.InlineExps
	} else if len(req.ExpPaths) > 0 {
		exps, err = loadExpsFromFiles(req.ExpPaths)
	} else {
		exps, err = loadExps(req.ExpDir)
	}
	if err != nil || len(exps) == 0 {
		http.Error(w, "load exps error or empty", http.StatusBadRequest)
		return
	}

	cc := req.Concurrency
	if cc <= 0 {
		cc = 20
	}

	providerName := strings.TrimSpace(req.Provider)
	var provider mcp.AIProvider
	if providerName != "" {
		p, err := newAIProvider(providerName, req.APIKey, req.BaseURL, req.Model)
		if err == nil {
			provider = p
		}
	}

	t := newTask(len(exps))
	go func() {
		sem := make(chan struct{}, cc)
		var wg sync.WaitGroup
		for _, e := range exps {
			select {
			case <-t.stop:
				break
			default:
			}
			wg.Add(1)
			sem <- struct{}{}
			es := e
			go func() {
				defer wg.Done()
				select {
				case <-t.stop:
					<-sem
					return
				default:
				}

				py := generatePythonFromExpSpec(req.TargetBaseURL, es)
				keyInfo := buildExpKeyInfo(req.TargetBaseURL, es)
				if provider != nil {
					tmp := requestExpFromAI(provider, es, nil)
					if strings.TrimSpace(tmp) != "" {
						py = tmp
					}
				}

				d, tot := t.IncDone()
				percent := int(math.Round(float64(d) / float64(tot) * 100))
				safeSend(t, SSEMessage{
					Type:     "find",
					TaskID:   t.ID,
					Progress: fmt.Sprintf("%d/%d", d, tot),
					Percent:  percent,
					Data: map[string]interface{}{
						"name":    es.Name,
						"keyInfo": keyInfo,
						"python":  py,
					},
				})

				<-sem
			}()
		}
		wg.Wait()
		finishTask(t.ID)
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"taskId": t.ID})
}
