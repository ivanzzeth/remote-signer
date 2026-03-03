package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ivanzzeth/remote-signer/internal/logger"
)

// SlackClient is the Slack API client for sending notifications.
type SlackClient struct {
	botToken   string
	httpClient *http.Client
}

// NewSlackClient creates a Slack client.
func NewSlackClient(botToken string) (*SlackClient, error) {
	if botToken == "" {
		return nil, fmt.Errorf("bot token is required")
	}

	return &SlackClient{
		botToken: botToken,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// GetChannelMembers returns channel member IDs, excluding bots.
func (s *SlackClient) GetChannelMembers(channelID string) ([]string, error) {
	url := fmt.Sprintf("https://slack.com/api/conversations.members?channel=%s", channelID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.botToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get channel members: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		OK      bool     `json:"ok"`
		Members []string `json:"members"`
		Error   string   `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !result.OK {
		return nil, fmt.Errorf("Slack API error: %s", result.Error)
	}

	log := logger.GetGlobal()
	log.Debug().
		Int("member_count", len(result.Members)).
		Str("channel_id", channelID).
		Msg("Retrieved members from channel")

	humanMembers, err := s.filterBots(result.Members)
	if err != nil {
		log.Warn().
			Err(err).
			Msg("Failed to filter bots, returning all members")
		return result.Members, nil
	}

	log.Debug().
		Int("human_members", len(humanMembers)).
		Int("total_members", len(result.Members)).
		Int("bots_excluded", len(result.Members)-len(humanMembers)).
		Msg("Filtered to human members")
	return humanMembers, nil
}

// GetUserInfo returns Slack user info for the given user ID.
func (s *SlackClient) GetUserInfo(userID string) (*UserInfo, error) {
	url := fmt.Sprintf("https://slack.com/api/users.info?user=%s", userID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.botToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		User  struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			RealName string `json:"real_name"`
		} `json:"user"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !result.OK {
		return nil, fmt.Errorf("Slack API error: %s", result.Error)
	}

	return &UserInfo{
		ID:       result.User.ID,
		Name:     result.User.Name,
		RealName: result.User.RealName,
	}, nil
}

// PostMessage sends a message to the given Slack channel.
func (s *SlackClient) PostMessage(channelID, message string) error {
	url := "https://slack.com/api/chat.postMessage"

	payload := map[string]interface{}{
		"channel": channelID,
		"text":    message,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.botToken)
	req.Header.Set("Content-Type", "application/json")

	log := logger.GetGlobal()
	log.Debug().
		Str("channel_id", channelID).
		Int("message_length", len(message)).
		Msg("Sending message to Slack channel")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		log.Error().
			Err(err).
			Str("channel_id", channelID).
			Msg("HTTP request failed when posting to Slack")
		return fmt.Errorf("failed to post message: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		Warning string `json:"warning,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Error().
			Err(err).
			Str("channel_id", channelID).
			Int("status_code", resp.StatusCode).
			Msg("Failed to decode Slack API response")
		return fmt.Errorf("failed to decode response: %w", err)
	}

	if !result.OK {
		log.Error().
			Str("channel_id", channelID).
			Str("slack_error", result.Error).
			Str("warning", result.Warning).
			Int("status_code", resp.StatusCode).
			Msg("Slack API returned error")
		return fmt.Errorf("Slack API error: %s", result.Error)
	}

	log.Info().
		Str("channel_id", channelID).
		Msg("Successfully posted message to Slack channel")
	return nil
}

// ReplyToChannel posts a reply to the channel (response_url from interaction payload).
func (s *SlackClient) ReplyToChannel(responseURL, message, responseType string) error {
	payload := map[string]interface{}{
		"text":          message,
		"response_type": responseType, // "in_channel" or "ephemeral"
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := s.httpClient.Post(responseURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to post response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Slack response error: status %d", resp.StatusCode)
	}

	log := logger.GetGlobal()
	log.Debug().Msg("Successfully replied to Slack channel")
	return nil
}

// UserInfo holds Slack user details.
type UserInfo struct {
	ID       string
	Name     string
	RealName string
}

// FindUserByName looks up a user ID by display name.
func (s *SlackClient) FindUserByName(username string) (string, error) {
	url := "https://slack.com/api/users.list"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.botToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get users list: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Members []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			RealName string `json:"real_name"`
			Deleted  bool   `json:"deleted"`
		} `json:"members"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if !result.OK {
		return "", fmt.Errorf("Slack API error: %s", result.Error)
	}

	usernameLower := strings.ToLower(username)
	for _, member := range result.Members {
		if member.Deleted {
			continue
		}
		if strings.ToLower(member.Name) == usernameLower {
			log := logger.GetGlobal()
			log.Debug().
				Str("username", username).
				Str("user_id", member.ID).
				Msg("Found user")
			return member.ID, nil
		}
	}

	return "", fmt.Errorf("user not found: @%s", username)
}

// filterBots returns only non-bot user IDs from the given list.
func (s *SlackClient) filterBots(userIDs []string) ([]string, error) {
	url := "https://slack.com/api/users.list"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.botToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		OK      bool `json:"ok"`
		Members []struct {
			ID      string `json:"id"`
			IsBot   bool   `json:"is_bot"`
			Deleted bool   `json:"deleted"`
		} `json:"members"`
		Error string `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !result.OK {
		return nil, fmt.Errorf("Slack API error: %s", result.Error)
	}

	botMap := make(map[string]bool)
	for _, member := range result.Members {
		if member.IsBot || member.Deleted {
			botMap[member.ID] = true
		}
	}

	humanMembers := make([]string, 0, len(userIDs))
	for _, userID := range userIDs {
		if !botMap[userID] {
			humanMembers = append(humanMembers, userID)
		}
	}

	return humanMembers, nil
}

// SendToChannels sends the message to multiple Slack channels.
func (s *SlackClient) SendToChannels(channelIDs []string, message string) error {
	if len(channelIDs) == 0 {
		return fmt.Errorf("channel IDs are required")
	}
	if message == "" {
		return fmt.Errorf("message is required")
	}

	log := logger.GetGlobal()
	var lastErr error
	successCount := 0

	for _, channelID := range channelIDs {
		if err := s.PostMessage(channelID, message); err != nil {
			lastErr = err
			log.Warn().
				Err(err).
				Str("channel_id", channelID).
				Msg("Failed to send message to channel")
			continue
		}
		successCount++
	}

	if successCount == 0 {
		return fmt.Errorf("failed to send to any channel: %w", lastErr)
	}

	if lastErr != nil {
		log.Warn().
			Int("success_count", successCount).
			Int("total_count", len(channelIDs)).
			Msg("Some channels failed to receive message")
	}

	return nil
}
