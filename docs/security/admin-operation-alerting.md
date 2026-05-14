# Real-Time Admin Operation Alerting

**Status**: Implemented
**Date**: 2026-03-16

## Overview

Every high-risk admin operation triggers a real-time notification via configured channels (Slack, Telegram, Pushover, Webhook). This enables immediate detection of unauthorized access — if you didn't initiate the operation, it may indicate a breach.

## Philosophy

> "If I did it, the alert is just a confirmation. If I didn't, it's an intrusion alarm."

All privileged write operations are monitored. The system doesn't distinguish between "expected" and "unexpected" — operators always receive alerts and decide whether to investigate.

## Monitored Operations

### Signer Management (Critical)
| Event | Alert Type | Trigger |
|-------|-----------|---------|
| Signer created (keystore/import) | `signer_created` | API: POST /signers |
| Signer unlocked | `signer_unlocked` | API: POST /signers/{addr}/unlock |
| Signer locked | `signer_locked` | API: POST /signers/{addr}/lock |
| Signer auto-locked (timeout) | `signer_auto_locked` | System: auto-lock timer |
| HD wallet created/imported | `hdwallet_created` | API: POST /hd-wallets |
| HD wallet addresses derived | `hdwallet_derived` | API: POST /hd-wallets/{addr}/derive |

### Rule Management (High)
| Event | Alert Type | Trigger |
|-------|-----------|---------|
| Rule created | `rule_created` | API: POST /rules |
| Rule updated | `rule_updated` | API: PUT /rules/{id} |
| Rule deleted | `rule_deleted` | API: DELETE /rules/{id} |
| Preset applied | `preset_applied` | API: POST /presets/{id}/apply |

### Configuration Sync (Medium)
| Event | Alert Type | Trigger |
|-------|-----------|---------|
| Config reloaded (SIGHUP) | `config_reloaded` | System: SIGHUP signal |
| Template created/updated/deleted | `template_synced` | Config sync (only on actual changes) |
| API key created/updated/deleted | `apikey_synced` | Config sync (only on actual changes) |

## Alert Format

```
[Remote Signer] ADMIN OPERATION

Operation: signer_created
API Key: admin
Source IP: 192.168.1.100
Detail: signer created: type=keystore
Time: 2026-03-16T10:30:00Z

If you did not initiate this, investigate immediately.
```

## Architecture

```
AuditLogger.log()
    │
    ├── Persist to DB (existing)
    │
    └── IsHighRiskEvent(eventType)?
         ├── No → done
         └── Yes → onHighRiskOperation callback
              │
              └── SecurityAlertService.Alert()
                   ├── Rate limited (per type+source, 5min cooldown)
                   └── NotifyService.SendWithPriority()
                        ├── Slack
                        ├── Telegram
                        ├── Pushover
                        └── Webhook
```

## Rate Limiting

Alerts are rate-limited per (alert_type, source_ip) with a 5-minute cooldown to prevent notification flooding during legitimate batch operations (e.g., config reload that syncs multiple templates).

## Configuration

No additional configuration needed. Alerts use the existing `notify_channels` config:

```yaml
notify_channels:
  slack:
    enabled: true
    bot_token: "${SLACK_BOT_TOKEN}"
    channel: "#security-alerts"
  telegram:
    enabled: true
    bot_token: "${TELEGRAM_BOT_TOKEN}"
    chat_id: "${TELEGRAM_CHAT_ID}"
```

## Security Considerations

1. **Non-blocking**: Alert delivery is async — never blocks the admin operation itself
2. **Fail-safe**: If notification delivery fails, the operation still succeeds (alert failure is logged)
3. **No sensitive data in alerts**: Alerts include operation type, API key ID, source IP, and a brief detail — no private keys, passwords, or transaction data
4. **Rate limiting prevents DoS**: An attacker who triggers many operations won't flood notification channels
