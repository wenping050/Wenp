package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
)

const (
	DefaultServerURL = "http://3.25.95.151:8000"
	fileName         = "auth.json"
)

// AuthInfo holds the active authorization state.
type AuthInfo struct {
	ServerURL string `json:"server_url"`
	Username  string `json:"username"`
	Token     string `json:"token"`
	ExpireAt  string `json:"expire_at"`
	DaysLeft  int    `json:"days_left"`
	LoggedIn  bool   `json:"logged_in"`
	MachineID string `json:"machine_id"`
	Error     string `json:"error,omitempty"`
}

// Manager controls the user authentication and license verification.
type Manager struct {
	mu     sync.RWMutex
	dir    string
	info   AuthInfo
	client *http.Client
}

// New creates and initializes an Auth Manager.
func New(dir string) *Manager {
	m := &Manager{
		dir: dir,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		info: AuthInfo{
			ServerURL: DefaultServerURL,
			DaysLeft:  -1,
		},
	}
	m.load()
	if m.info.MachineID == "" {
		m.info.MachineID = getMachineID()
		_ = m.save()
	}
	// Verify token in background if credentials exist
	if m.info.LoggedIn && m.info.Token != "" {
		go func() {
			_, _ = m.Verify()
		}()
	}
	return m
}

func getMachineID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		if val, _, err := k.GetStringValue("MachineGuid"); err == nil && val != "" {
			return val
		}
	}
	// Fallback: random hex
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *Manager) path() string {
	return filepath.Join(m.dir, fileName)
}

func (m *Manager) load() {
	b, err := os.ReadFile(m.path())
	if err != nil {
		return
	}
	var info AuthInfo
	if err := json.Unmarshal(b, &info); err == nil {
		if info.ServerURL == "" {
			info.ServerURL = DefaultServerURL
		}
		m.info = info
	}
}

func (m *Manager) save() error {
	_ = os.MkdirAll(m.dir, 0o755)
	b, err := json.MarshalIndent(m.info, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.path(), b, 0o600)
}

// Status returns a copy of the current authorization info.
func (m *Manager) Status() AuthInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.info
}

// IsAuthorized checks whether the user is logged in with active days remaining.
func (m *Manager) IsAuthorized() (bool, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.info.LoggedIn {
		return false, "请先登录授权账号"
	}
	if m.info.DaysLeft <= 0 {
		return false, fmt.Sprintf("账号已到期 (%s)，请续费或使用卡密激活", m.info.ExpireAt)
	}
	return true, ""
}

// Login authenticates with username, password, and machine ID.
func (m *Manager) Login(username, password string) (*AuthInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	reqBody, _ := json.Marshal(map[string]string{
		"username":   username,
		"password":   password,
		"machine_id": m.info.MachineID,
	})

	url := fmt.Sprintf("%s/api/auth/login", m.info.ServerURL)
	resp, err := m.client.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("连接授权服务器失败: %w", err)
	}
	defer resp.Body.Close()

	var res struct {
		OK       bool   `json:"ok"`
		Msg      string `json:"msg"`
		Token    string `json:"token"`
		ExpireAt string `json:"expire_at"`
		DaysLeft int    `json:"days_left"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("解析服务器响应失败: %w", err)
	}

	if !res.OK {
		return nil, fmt.Errorf("%s", res.Msg)
	}

	m.info.Username = username
	m.info.Token = res.Token
	m.info.ExpireAt = res.ExpireAt
	m.info.DaysLeft = res.DaysLeft
	m.info.LoggedIn = true
	m.info.Error = ""
	_ = m.save()

	copyInfo := m.info
	return &copyInfo, nil
}

// Verify validates the saved token with the authorization server.
func (m *Manager) Verify() (*AuthInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.info.LoggedIn || m.info.Token == "" {
		copyInfo := m.info
		return &copyInfo, nil
	}

	reqBody, _ := json.Marshal(map[string]string{
		"username":   m.info.Username,
		"token":      m.info.Token,
		"machine_id": m.info.MachineID,
	})

	url := fmt.Sprintf("%s/api/auth/verify", m.info.ServerURL)
	resp, err := m.client.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		// Network offline: do not forcefully log out immediately
		copyInfo := m.info
		return &copyInfo, nil
	}
	defer resp.Body.Close()

	var res struct {
		OK       bool   `json:"ok"`
		Msg      string `json:"msg"`
		ExpireAt string `json:"expire_at"`
		DaysLeft int    `json:"days_left"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		copyInfo := m.info
		return &copyInfo, nil
	}

	if !res.OK {
		m.info.Error = res.Msg
		if res.DaysLeft == 0 {
			m.info.DaysLeft = 0
		} else {
			m.info.LoggedIn = false
		}
		_ = m.save()
		return nil, fmt.Errorf("%s", res.Msg)
	}

	m.info.ExpireAt = res.ExpireAt
	m.info.DaysLeft = res.DaysLeft
	m.info.Error = ""
	_ = m.save()

	copyInfo := m.info
	return &copyInfo, nil
}

// Redeem recharges authorization using a card key.
func (m *Manager) Redeem(cardKey string) (*AuthInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.info.LoggedIn || m.info.Username == "" {
		return nil, fmt.Errorf("请先登录账号后再使用卡密")
	}

	reqBody, _ := json.Marshal(map[string]string{
		"username": m.info.Username,
		"card_key": cardKey,
	})

	url := fmt.Sprintf("%s/api/auth/redeem", m.info.ServerURL)
	resp, err := m.client.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("连接授权服务器失败: %w", err)
	}
	defer resp.Body.Close()

	var res struct {
		OK       bool   `json:"ok"`
		Msg      string `json:"msg"`
		ExpireAt string `json:"expire_at"`
		DaysLeft int    `json:"days_left"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("解析服务器响应失败: %w", err)
	}

	if !res.OK {
		return nil, fmt.Errorf("%s", res.Msg)
	}

	m.info.ExpireAt = res.ExpireAt
	m.info.DaysLeft = res.DaysLeft
	m.info.Error = ""
	_ = m.save()

	copyInfo := m.info
	return &copyInfo, nil
}

// Logout clears the stored session and logs out.
func (m *Manager) Logout() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.info.Username = ""
	m.info.Token = ""
	m.info.ExpireAt = ""
	m.info.DaysLeft = 0
	m.info.LoggedIn = false
	m.info.Error = ""
	_ = m.save()
}
