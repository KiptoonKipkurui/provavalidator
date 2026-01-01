package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type OSVClient struct {
	BaseURl    string
	HTTPClient *http.Client

	// MaxQueriesPerBatch lets you chunk big SBOMs safely
	MaxQueriesPerBatch int
}

func NewOSVClient() *OSVClient {
	return &OSVClient{
		BaseURl: "https://api.osv.dev",
		HTTPClient: &http.Client{
			Timeout: 20 * time.Second,
		},
		MaxQueriesPerBatch: 200,
	}
}

func (c *OSVClient) QueryBatch(ctx context.Context, queries []osvQuery) ([]osvQueryResult, error) {
	if len(queries) == 0 {
		return nil, nil
	}

	if c.HTTPClient == nil {
		c.HTTPClient = http.DefaultClient
	}

	if c.BaseURl == "" {
		c.BaseURl = "https://api.osv.dev"
	}

	if c.MaxQueriesPerBatch <= 0 {
		c.MaxQueriesPerBatch = 200
	}
	all := make([]osvQueryResult, 0, len(queries))

	for start := 0; start < len(queries); start += c.MaxQueriesPerBatch {
		end := start + c.MaxQueriesPerBatch

		if end > len(queries) {
			end = len(queries)
		}

		reqBody := osvQueryBatchRequest{
			Queries: queries[start:end],
		}

		b, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("osv: marshal querybatch: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURl+"/v1/querybatch", bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("osv: build request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("osv: http request: %w", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("osv: http %d: %s", resp.StatusCode, string(body))
		}
		var out osvQueryBatchResponse

		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("osv: decode response: %w", err)
		}
		all = append(all, out.Results...)
	}

	// OSV returns results alligned with queries order.
	if len(all) != len(queries) {
		return nil, fmt.Errorf("osv: result count mismatch: got %d, want %d", len(all), len(queries))
	}

	return all, nil
}
