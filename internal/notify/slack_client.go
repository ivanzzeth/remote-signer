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

// SlackClient Slack API客户端
type SlackClient struct {
	botToken   string
	httpClient *http.Client
}

// NewSlackClient 创建Slack客户端
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

// GetChannelMembers 获取频道成员列表（排除bot）
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

	// 过滤掉bot用户
	humanMembers, err := s.filterBots(result.Members)
	if err != nil {
		log.Warn().
			Err(err).
			Msg("Failed to filter bots, returning all members")
		return result.Members, nil // 如果过滤失败，返回所有成员
	}

	log.Debug().
		Int("human_members", len(humanMembers)).
		Int("total_members", len(result.Members)).
		Int("bots_excluded", len(result.Members)-len(humanMembers)).
		Msg("Filtered to human members")
	return humanMembers, nil
}

// GetUserInfo 获取用户信息
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

// PostMessage 发送消息到指定频道
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

// ReplyToChannel 回复消息到频道
func (s *SlackClient) ReplyToChannel(responseURL, message, responseType string) error {
	payload := map[string]interface{}{
		"text":          message,
		"response_type": responseType, // in_channel 或 ephemeral
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

// UserInfo Slack用户信息
type UserInfo struct {
	ID       string
	Name     string
	RealName string
}

// FindUserByName 通过用户名查找用户ID
func (s *SlackClient) FindUserByName(username string) (string, error) {
	// 获取所有用户列表
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

	// 查找匹配的用户名（不区分大小写）
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

// filterBots 过滤掉bot用户，只返回真实用户
func (s *SlackClient) filterBots(userIDs []string) ([]string, error) {
	// 获取所有用户信息
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

	// 创建bot用户ID的映射
	botMap := make(map[string]bool)
	for _, member := range result.Members {
		if member.IsBot || member.Deleted {
			botMap[member.ID] = true
		}
	}

	// 过滤掉bot和已删除用户
	humanMembers := make([]string, 0, len(userIDs))
	for _, userID := range userIDs {
		if !botMap[userID] {
			humanMembers = append(humanMembers, userID)
		}
	}

	return humanMembers, nil
}

// SendToChannels 向多个Slack频道发送消息
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
