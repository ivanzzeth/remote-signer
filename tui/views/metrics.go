package views

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/tui/styles"
)

// metricsProvider is the interface for fetching metrics.
type metricsProvider interface {
	Metrics(ctx context.Context) (string, error)
}

// latencyRow holds p50/p95 in seconds for display.
type latencyRow struct {
	label string
	p50   float64
	p95   float64
}

type bucketPoint struct {
	le    float64
	count float64
}

type MetricsModel struct {
	metrics  metricsProvider
	ctx      context.Context
	width    int
	height   int
	viewport viewport.Model
	ready    bool

	spinner spinner.Model
	loading bool
	err     error

	lastRefresh time.Time
	raw         string
	showRaw     bool

	signCounts  map[string]float64 // outcome -> count
	ruleCounts  map[string]float64  // outcome -> count
	signLatency []latencyRow        // per (chain_type, sign_type)
	ruleLatency []latencyRow        // per rule_type
}

type MetricsDataMsg struct {
	Raw string
	Err error
}

func NewMetricsModel(c *client.Client, ctx context.Context) (*MetricsModel, error) {
	if c == nil {
		return nil, fmt.Errorf("client is required")
	}
	return newMetricsModelFromProvider(c, ctx)
}

// newMetricsModelFromProvider creates a metrics model from a metricsProvider (for testing).
func newMetricsModelFromProvider(mp metricsProvider, ctx context.Context) (*MetricsModel, error) {
	if mp == nil {
		return nil, fmt.Errorf("client is required")
	}
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = styles.SpinnerStyle

	return &MetricsModel{
		metrics:    mp,
		ctx:        ctx,
		spinner:    s,
		loading:    true,
		signCounts: map[string]float64{},
		ruleCounts: map[string]float64{},
	}, nil
}

func (m *MetricsModel) Init() tea.Cmd {
	return tea.Batch(
		m.spinner.Tick,
		m.loadMetrics(),
	)
}

func (m *MetricsModel) SetSize(width, height int) {
	m.width = width
	m.height = height

	headerHeight := 3
	footerHeight := 2
	viewportHeight := height - headerHeight - footerHeight
	if viewportHeight < 1 {
		viewportHeight = 1
	}

	if !m.ready {
		m.viewport = viewport.New(width, viewportHeight)
		m.viewport.Style = lipgloss.NewStyle()
		m.ready = true
	} else {
		m.viewport.Width = width
		m.viewport.Height = viewportHeight
	}
}

func (m *MetricsModel) Refresh() tea.Cmd {
	m.loading = true
	return tea.Batch(
		m.spinner.Tick,
		m.loadMetrics(),
	)
}

func (m *MetricsModel) loadMetrics() tea.Cmd {
	return func() tea.Msg {
		raw, err := m.metrics.Metrics(m.ctx)
		if err != nil {
			return MetricsDataMsg{Err: err}
		}
		return MetricsDataMsg{Raw: raw}
	}
}

func (m *MetricsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case MetricsDataMsg:
		m.loading = false
		if msg.Err != nil {
			m.err = msg.Err
			return m, nil
		}

		m.err = nil
		m.raw = msg.Raw
		m.lastRefresh = time.Now()
		m.signCounts, m.ruleCounts = parsePrometheusCounts(msg.Raw)
		m.signLatency, m.ruleLatency = parsePrometheusLatency(msg.Raw)
		return m, nil

	case spinner.TickMsg:
		if m.loading {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "r":
			return m, m.Refresh()
		case "t":
			m.showRaw = !m.showRaw
			return m, nil
		case "up", "k":
			m.viewport.LineUp(1)
			return m, nil
		case "down", "j":
			m.viewport.LineDown(1)
			return m, nil
		case "pgup", "ctrl+u":
			m.viewport.HalfViewUp()
			return m, nil
		case "pgdown", "ctrl+d":
			m.viewport.HalfViewDown()
			return m, nil
		case "home", "g":
			m.viewport.GotoTop()
			return m, nil
		case "end", "G":
			m.viewport.GotoBottom()
			return m, nil
		}
	}

	return m, nil
}

func (m *MetricsModel) View() string {
	if m.loading {
		return lipgloss.Place(
			m.width,
			m.height,
			lipgloss.Center,
			lipgloss.Center,
			fmt.Sprintf("%s Loading metrics...", m.spinner.View()),
		)
	}

	if m.err != nil {
		errBox := styles.BoxStyle.
			BorderForeground(styles.ErrorColor).
			Render(fmt.Sprintf("Error: %v\n\nPress r to retry", m.err))
		return lipgloss.Place(
			m.width,
			m.height,
			lipgloss.Center,
			lipgloss.Center,
			errBox,
		)
	}

	var content strings.Builder

	content.WriteString(styles.SubtitleStyle.Render("Sign Requests (counts by outcome)"))
	content.WriteString("\n")
	content.WriteString(renderBarTable(m.signCounts, m.width))
	content.WriteString("\n\n")

	content.WriteString(styles.SubtitleStyle.Render("Rule Evaluations (counts by outcome)"))
	content.WriteString("\n")
	content.WriteString(renderBarTable(m.ruleCounts, m.width))
	content.WriteString("\n\n")

	content.WriteString(styles.SubtitleStyle.Render("Latency (p50/p95, seconds)"))
	content.WriteString("\n")
	content.WriteString(renderLatencyTable(m.signLatency, m.ruleLatency))
	content.WriteString("\n")

	if m.showRaw {
		content.WriteString("\n")
		content.WriteString(styles.SubtitleStyle.Render("Raw (toggle)"))
		content.WriteString("\n")
		content.WriteString(styles.BoxStyle.Render(strings.TrimRight(m.raw, "\n")))
		content.WriteString("\n")
	} else {
		content.WriteString("\n")
		content.WriteString(styles.SubtitleStyle.Render("Raw (toggle)"))
		content.WriteString("\n")
		content.WriteString(styles.MutedColor.Render("  remote_signer_rule_evaluation_total{rule_type=\"...\",outcome=\"allow\"} 100"))
		content.WriteString("\n")
		content.WriteString(styles.MutedColor.Render("  ..."))
		content.WriteString("\n")
	}

	m.viewport.SetContent(content.String())

	var view strings.Builder
	view.WriteString(styles.TitleStyle.Render("Metrics"))
	view.WriteString("\n")
	if !m.lastRefresh.IsZero() {
		view.WriteString(styles.MutedColor.Render(fmt.Sprintf("Last refresh: %s", m.lastRefresh.Format("2006-01-02 15:04:05"))))
	}
	view.WriteString("\n\n")

	view.WriteString(m.viewport.View())
	view.WriteString("\n")

	scrollInfo := fmt.Sprintf("(%d%% scrolled)", int(m.viewport.ScrollPercent()*100))
	helpText := "j/k: scroll | g/G: top/bottom | r: refresh | t: toggle raw"
	view.WriteString(styles.HelpStyle.Render(fmt.Sprintf("%s  %s", scrollInfo, helpText)))

	return view.String()
}

func parsePrometheusCounts(raw string) (signCounts map[string]float64, ruleCounts map[string]float64) {
	signCounts = map[string]float64{}
	ruleCounts = map[string]float64{}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		metricAndLabels, valueStr, ok := splitSampleLine(line)
		if !ok {
			continue
		}

		value, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			continue
		}

		name, labels := parseMetricAndLabels(metricAndLabels)

		switch name {
		case "remote_signer_sign_request_duration_seconds_count":
			outcome := labels["outcome"]
			if outcome != "" {
				signCounts[outcome] += value
			}
		case "remote_signer_rule_evaluation_total":
			outcome := labels["outcome"]
			if outcome != "" {
				ruleCounts[outcome] += value
			}
		}
	}

	return signCounts, ruleCounts
}

// parsePrometheusLatency parses histogram buckets and returns p50/p95 per series.
// For sign_request we use the series (chain_type, sign_type, outcome) with largest total for that (chain_type, sign_type).
func parsePrometheusLatency(raw string) (signLatency []latencyRow, ruleLatency []latencyRow) {
	// sign: full label key "chain_type,sign_type,outcome" -> list of (le, count) for that series
	signSeries := map[string][]bucketPoint{}
	ruleBuckets := map[string][]bucketPoint{}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		metricAndLabels, valueStr, ok := splitSampleLine(line)
		if !ok {
			continue
		}
		value, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			continue
		}
		name, labels := parseMetricAndLabels(metricAndLabels)
		leStr := labels["le"]
		if leStr == "" {
			continue
		}
		le := parseLe(leStr)
		if le < 0 {
			continue
		}

		switch name {
		case "remote_signer_sign_request_duration_seconds_bucket":
			ct := labels["chain_type"]
			st := labels["sign_type"]
			outcome := labels["outcome"]
			if ct == "" || st == "" {
				continue
			}
			key := ct + "," + st + "," + outcome
			signSeries[key] = append(signSeries[key], bucketPoint{le: le, count: value})
		case "remote_signer_rule_evaluation_duration_seconds_bucket":
			rt := labels["rule_type"]
			if rt == "" {
				continue
			}
			ruleBuckets[rt] = append(ruleBuckets[rt], bucketPoint{le: le, count: value})
		}
	}

	// For sign: group by (chain_type, sign_type), pick series with max +Inf count, then compute p50/p95
	signLatency = computeSignLatencyRows(signSeries)
	ruleLatency = computeLatencyRows(ruleBuckets, func(key string) string {
		return "rule_eval (" + key + ")"
	})
	return signLatency, ruleLatency
}

func computeSignLatencyRows(series map[string][]bucketPoint) []latencyRow {
	// Group by (chain_type, sign_type) and find best series (max total)
	type keyCount struct {
		key   string // "chain_type,sign_type"
		total float64
		points []bucketPoint
	}
	byGroup := map[string]keyCount{}
	for fullKey, points := range series {
		parts := strings.Split(fullKey, ",")
		if len(parts) < 3 {
			continue
		}
		groupKey := parts[0] + "," + parts[1]
		var total float64
		for _, p := range points {
			if p.le == math.MaxFloat64 {
				total = p.count
				break
			}
		}
		if cur, ok := byGroup[groupKey]; !ok || total > cur.total {
			byGroup[groupKey] = keyCount{key: groupKey, total: total, points: points}
		}
	}
	var rows []latencyRow
	for _, kc := range byGroup {
		p50, p95 := percentileFromBucketPoints(kc.points)
		parts := strings.SplitN(kc.key, ",", 2)
		label := kc.key
		if len(parts) == 2 {
			label = "sign_request (" + parts[0] + ", " + parts[1] + ")"
		}
		rows = append(rows, latencyRow{label: label, p50: p50, p95: p95})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].label < rows[j].label })
	return rows
}

func parseLe(s string) float64 {
	if s == "+Inf" || s == "+inf" {
		return math.MaxFloat64
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return -1
	}
	return f
}

func percentileFromBucketPoints(points []bucketPoint) (p50, p95 float64) {
	// Prometheus histogram bucket values are cumulative: value at le = count(observations <= le).
	// So total = value at le=+Inf; we use each bucket's value directly as cum, do not sum.
	byLe := map[float64]float64{}
	for _, p := range points {
		byLe[p.le] = p.count
	}
	var sorted []bucketPoint
	for le, count := range byLe {
		sorted = append(sorted, bucketPoint{le: le, count: count})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].le < sorted[j].le })
	// Total is the cumulative count at +Inf (last bucket)
	var total float64
	for _, p := range sorted {
		if p.le == math.MaxFloat64 {
			total = p.count
			break
		}
	}
	if total == 0 {
		return 0, 0
	}
	for _, p := range sorted {
		// p.count is already cumulative
		if p50 == 0 && p.count >= 0.5*total {
			p50 = p.le
		}
		if p95 == 0 && p.count >= 0.95*total {
			p95 = p.le
		}
	}
	if p95 == 0 {
		p95 = p50
	}
	if p50 == math.MaxFloat64 {
		p50 = 0
	}
	if p95 == math.MaxFloat64 {
		p95 = p50
	}
	return p50, p95
}

func computeLatencyRows(bucketsByKey map[string][]bucketPoint, labelFn func(string) string) []latencyRow {
	var rows []latencyRow
	for key, points := range bucketsByKey {
		p50, p95 := percentileFromBucketPoints(points)
		rows = append(rows, latencyRow{
			label: labelFn(key),
			p50:   p50,
			p95:   p95,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].label < rows[j].label })
	return rows
}

func renderLatencyTable(signRows, ruleRows []latencyRow) string {
	if len(signRows) == 0 && len(ruleRows) == 0 {
		return styles.MutedColor.Render("No data")
	}
	var b strings.Builder
	for _, r := range signRows {
		b.WriteString(fmt.Sprintf("    %-32s  p50 %.2f   p95 %.2f\n", r.label, r.p50, r.p95))
	}
	for _, r := range ruleRows {
		b.WriteString(fmt.Sprintf("    %-32s  p50 %.2f   p95 %.2f\n", r.label, r.p50, r.p95))
	}
	return strings.TrimRight(b.String(), "\n")
}

func splitSampleLine(line string) (metricAndLabels string, value string, ok bool) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func parseMetricAndLabels(s string) (name string, labels map[string]string) {
	labels = map[string]string{}

	open := strings.IndexByte(s, '{')
	if open == -1 {
		return s, labels
	}
	close := strings.LastIndexByte(s, '}')
	if close == -1 || close < open {
		return s, labels
	}

	name = s[:open]
	labelStr := s[open+1 : close]
	for _, kv := range splitLabels(labelStr) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, "\"")
		labels[k] = v
	}

	return name, labels
}

func splitLabels(s string) []string {
	// Prometheus label values are quoted strings; for our use cases labels do not contain unescaped commas.
	// Keep implementation intentionally small and robust for this project's known metrics.
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func renderBarTable(counts map[string]float64, width int) string {
	if len(counts) == 0 {
		return styles.MutedColor.Render("No data")
	}

	type row struct {
		key   string
		value float64
	}
	var rows []row
	var max float64
	for k, v := range counts {
		rows = append(rows, row{key: k, value: v})
		if v > max {
			max = v
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].value > rows[j].value })

	labelWidth := 10
	valueWidth := 10
	barMax := width - (2 + labelWidth + 2 + valueWidth + 2)
	if barMax < 10 {
		barMax = 10
	}
	if barMax > 40 {
		barMax = 40
	}

	var b strings.Builder
	for _, r := range rows {
		barLen := 0
		if max > 0 {
			barLen = int((r.value / max) * float64(barMax))
		}
		if barLen < 0 {
			barLen = 0
		}
		if barLen > barMax {
			barLen = barMax
		}
		bar := strings.Repeat("#", barLen)
		if bar == "" {
			bar = " "
		}
		b.WriteString(fmt.Sprintf("  %-*s  %-*s  %.0f\n", labelWidth, r.key, barMax, bar, r.value))
	}
	return strings.TrimRight(b.String(), "\n")
}
