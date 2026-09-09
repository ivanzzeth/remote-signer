package ports

// NotifyChannel lists the destinations a message should reach.
//
// It is plain data — no transport, no credentials — which is why it can sit in
// the use-case layer: a service deciding *that* an operator should be told
// names the audience, and something else knows how to reach them.
// Channel specifies which concrete channels to deliver to.
type NotifyChannel struct {
	Slack    []string `yaml:"slack,omitempty"`    // Slack channel IDs
	Pushover []string `yaml:"pushover,omitempty"` // Pushover user keys
	Webhook  []string `yaml:"webhook,omitempty"`  // Webhook URLs
	Telegram []string `yaml:"telegram,omitempty"` // Telegram chat IDs or @channel
}

// Notifier is what the use-case layer needs to reach an operator.
//
// ⚠️ Two methods rather than *notify.NotifyService. The services asked for the
// concrete type, so approval-guard and notifier logic depended on the transport
// package — Slack, Pushover, Telegram and webhook clients — to call Send.
//
// Nil is legal: notification is optional, and a service that requires a
// notifier makes alerting a hard dependency of signing.
type Notifier interface {
	Send(channel *NotifyChannel, message string) error
	SendWithPriority(channel *NotifyChannel, message string, priority int, sound string) error
}
