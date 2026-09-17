package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const (
	WebPort    = ":2053"
	DataFolder = "/app/data"
	ConfigFile = "/app/data/settings.json"
	CookieName = "bermuda_session"
	SaltKey    = "BERMUDA1998_SECURE_SALT_V1"
)

type Settings struct {
	UserHash  string `json:"user_hash"`
	PassHash  string `json:"pass_hash"`
	IsDefault bool   `json:"is_default"`
	Host      string `json:"host"`
	Port      string `json:"port"`
}

func getInitialHash() string {
	raw := string([]byte{67, 97, 122, 97, 114, 115, 101, 110, 115, 101, 49, 50, 51, 52})
	return hashString(raw)
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func sessionSecret(s Settings) string {
	return hashString(s.UserHash + ":" + s.PassHash + ":" + SaltKey)
}

func startXray() {
	cmd := exec.Command("/usr/local/bin/xray", "run", "-config", "/app/config.json")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Printf("Xray launch error: %v\n", err)
	}
}

func getSettings() Settings {
	initH := getInitialHash()
	s := Settings{
		UserHash:  initH,
		PassHash:  initH,
		IsDefault: true,
	}

	b, err := os.ReadFile(ConfigFile)
	if err == nil {
		_ = json.Unmarshal(b, &s)
		if s.UserHash == "" || s.PassHash == "" || s.UserHash == "7eb024765955fe4aa6203cfc4cfc623bca0484742f9b8c0c4c478a87da48c9ae" {
			s.UserHash = initH
			s.PassHash = initH
			s.IsDefault = true
			saveSettings(s)
		}
	} else {
		saveSettings(s)
	}
	return s
}

func saveSettings(s Settings) {
	_ = os.MkdirAll(DataFolder, 0755)
	b, _ := json.Marshal(s)
	_ = os.WriteFile(ConfigFile, b, 0644)
}

func checkAuth(r *http.Request, s Settings) bool {
	cookie, err := r.Cookie(CookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	return cookie.Value == sessionSecret(s)
}

func setAuthCookie(w http.ResponseWriter, s Settings) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    sessionSecret(s),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 30,
	})
}

func parseEndpoint(input string) (string, string) {
	s := strings.TrimSpace(input)
	s = strings.TrimPrefix(s, "tcp://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")

	if strings.Contains(s, ":") {
		parts := strings.Split(s, ":")
		if len(parts) == 2 {
			host := strings.TrimSpace(parts[0])
			port := strings.TrimSpace(parts[1])
			if _, err := strconv.Atoi(port); err == nil {
				return host, port
			}
		}
	}
	return s, ""
}

func main() {
	startXray()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		current := getSettings()
		if !checkAuth(r, current) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if current.IsDefault {
			http.Redirect(w, r, "/onboarding", http.StatusSeeOther)
			return
		}

		if r.Method == http.MethodPost {
			action := r.FormValue("action")
			if action == "save_connection" {
				endpoint := r.FormValue("endpoint")
				h, p := parseEndpoint(endpoint)
				if h != "" && p != "" {
					current.Host = h
					current.Port = p
					saveSettings(current)
				}
			} else if action == "save_security" {
				newU := strings.TrimSpace(r.FormValue("new_username"))
				newP := strings.TrimSpace(r.FormValue("new_password"))
				if newU != "" && newP != "" {
					current.UserHash = hashString(newU)
					current.PassHash = hashString(newP)
					current.IsDefault = false
					saveSettings(current)
					setAuthCookie(w, current)
				}
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		displayEndpoint := ""
		if current.Host != "" && current.Port != "" {
			displayEndpoint = current.Host + ":" + current.Port
		}

		html := strings.ReplaceAll(dashboardHTML, "{{ENDPOINT}}", displayEndpoint)
		html = strings.ReplaceAll(html, "{{HOST}}", current.Host)
		html = strings.ReplaceAll(html, "{{PORT}}", current.Port)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, html)
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		current := getSettings()

		if r.Method == http.MethodPost {
			user := strings.TrimSpace(r.FormValue("username"))
			pass := strings.TrimSpace(r.FormValue("password"))

			if hashString(user) == current.UserHash && hashString(pass) == current.PassHash {
				setAuthCookie(w, current)
				if current.IsDefault {
					http.Redirect(w, r, "/onboarding", http.StatusSeeOther)
					return
				}
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
			return
		}

		errNotice := ""
		if r.URL.Query().Get("error") == "1" {
			errNotice = `<div class="error-msg">AUTHENTICATION FAILED: INVALID CREDENTIALS</div>`
		}

		html := strings.ReplaceAll(loginHTML, "{{ERROR}}", errNotice)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, html)
	})

	http.HandleFunc("/onboarding", func(w http.ResponseWriter, r *http.Request) {
		current := getSettings()
		if !checkAuth(r, current) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if !current.IsDefault {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		if r.Method == http.MethodPost {
			newU := strings.TrimSpace(r.FormValue("new_username"))
			newP := strings.TrimSpace(r.FormValue("new_password"))
			initH := getInitialHash()

			if newU != "" && newP != "" && (hashString(newU) != initH || hashString(newP) != initH) {
				current.UserHash = hashString(newU)
				current.PassHash = hashString(newP)
				current.IsDefault = false
				saveSettings(current)
				setAuthCookie(w, current)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/onboarding?error=1", http.StatusSeeOther)
			return
		}

		errNotice := ""
		if r.URL.Query().Get("error") == "1" {
			errNotice = `<div class="error-msg">CREDENTIALS CANNOT MATCH DEFAULT VALUES</div>`
		}

		html := strings.ReplaceAll(onboardingHTML, "{{ERROR}}", errNotice)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, html)
	})

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	fmt.Printf("BERMUDA1998 Monochrome Core running on port %s\n", WebPort)
	_ = http.ListenAndServe(WebPort, nil)
}

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BERMUDA1998 - ACCESS</title>
<style>
  * { box-sizing: border-box; }
  body { background: #050505; color: #ededed; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  .card { background: #0c0c0d; padding: 2.2rem; border-radius: 8px; width: 100%; max-width: 360px; border: 1px solid #222225; box-shadow: 0 20px 40px rgba(0,0,0,0.8); }
  h2 { text-align: center; margin: 0 0 1.5rem 0; color: #ffffff; font-size: 0.95rem; letter-spacing: 0.15em; text-transform: uppercase; font-weight: 700; border-bottom: 1px solid #222225; padding-bottom: 1rem; }
  .error-msg { border: 1px solid #52525b; background: rgba(255,255,255,0.03); color: #e4e4e7; font-size: 0.75rem; padding: 0.6rem; border-radius: 4px; margin-bottom: 1.2rem; text-align: center; font-family: monospace; }
  label { display: block; font-size: 0.72rem; margin-bottom: 0.4rem; color: #88888e; text-transform: uppercase; letter-spacing: 0.05em; }
  input { width: 100%; padding: 0.75rem; margin-bottom: 1.2rem; border-radius: 4px; border: 1px solid #26262a; background: #000000; color: #ffffff; font-size: 0.85rem; font-family: inherit; transition: 0.2s; }
  input:focus { border-color: #ffffff; outline: none; }
  button { width: 100%; padding: 0.8rem; border-radius: 4px; border: none; background: #ffffff; color: #000000; font-weight: 700; cursor: pointer; font-size: 0.8rem; letter-spacing: 0.05em; text-transform: uppercase; transition: 0.2s; }
  button:hover { background: #d4d4d8; }
</style>
</head>
<body>
<div class="card">
  <h2>BERMUDA1998</h2>
  {{ERROR}}
  <form method="POST">
    <label>Operator ID</label>
    <input type="text" name="username" required autofocus autocomplete="off">
    <label>Access Key</label>
    <input type="password" name="password" required>
    <button type="submit">Authorize</button>
  </form>
</div>
</body>
</html>`

const onboardingHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BERMUDA1998 - SECURITY INITIALIZATION</title>
<style>
  * { box-sizing: border-box; }
  body { background: #050505; color: #ededed; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  .card { background: #0c0c0d; padding: 2.2rem; border-radius: 8px; width: 100%; max-width: 380px; border: 1px solid #222225; box-shadow: 0 20px 40px rgba(0,0,0,0.8); }
  h2 { text-align: center; margin: 0 0 0.5rem 0; color: #ffffff; font-size: 0.95rem; letter-spacing: 0.15em; text-transform: uppercase; font-weight: 700; }
  p { font-size: 0.78rem; color: #71717a; text-align: center; margin-bottom: 1.5rem; line-height: 1.5; border-bottom: 1px solid #222225; padding-bottom: 1rem; }
  .error-msg { border: 1px solid #52525b; background: rgba(255,255,255,0.03); color: #e4e4e7; font-size: 0.75rem; padding: 0.6rem; border-radius: 4px; margin-bottom: 1.2rem; text-align: center; font-family: monospace; }
  label { display: block; font-size: 0.72rem; margin-bottom: 0.4rem; color: #88888e; text-transform: uppercase; letter-spacing: 0.05em; }
  input { width: 100%; padding: 0.75rem; margin-bottom: 1.2rem; border-radius: 4px; border: 1px solid #26262a; background: #000000; color: #ffffff; font-size: 0.85rem; font-family: inherit; transition: 0.2s; }
  input:focus { border-color: #ffffff; outline: none; }
  button { width: 100%; padding: 0.8rem; border-radius: 4px; border: none; background: #ffffff; color: #000000; font-weight: 700; cursor: pointer; font-size: 0.8rem; letter-spacing: 0.05em; text-transform: uppercase; transition: 0.2s; }
  button:hover { background: #d4d4d8; }
</style>
</head>
<body>
<div class="card">
  <h2>Security Enforcement</h2>
  <p>Default credentials must be updated before initializing access.</p>
  {{ERROR}}
  <form method="POST">
    <label>New Operator ID</label>
    <input type="text" name="new_username" required autofocus autocomplete="off">
    <label>New Access Key</label>
    <input type="password" name="new_password" required>
    <button type="submit">Commit & Initialize</button>
  </form>
</div>
</body>
</html>`

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BERMUDA1998 CORE</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<style>
  * { box-sizing: border-box; }
  body { background: #050505; color: #d4d4d8; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; margin: 0; padding: 2rem 1rem; display: flex; justify-content: center; }
  .box { width: 100%; max-width: 480px; background: #0c0c0d; padding: 2rem; border-radius: 8px; border: 1px solid #222225; box-shadow: 0 25px 50px rgba(0,0,0,0.9); }
  
  .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; border-bottom: 1px solid #222225; padding-bottom: 1rem; }
  .logo-tag { display: flex; align-items: center; gap: 0.5rem; }
  .logo-tag h1 { font-size: 0.95rem; color: #ffffff; margin: 0; letter-spacing: 0.12em; font-weight: 700; }
  .badge { font-size: 0.65rem; background: #18181b; color: #a1a1aa; border: 1px solid #27272a; padding: 0.15rem 0.4rem; border-radius: 3px; letter-spacing: 0.05em; }
  .exit { color: #71717a; text-decoration: none; font-size: 0.75rem; border: 1px solid #27272a; padding: 0.3rem 0.6rem; border-radius: 4px; transition: 0.2s; }
  .exit:hover { color: #ffffff; border-color: #52525b; }

  .step-label { display: block; font-size: 0.72rem; margin-bottom: 0.45rem; color: #71717a; text-transform: uppercase; letter-spacing: 0.06em; }
  input { width: 100%; padding: 0.75rem; margin-bottom: 0.8rem; border-radius: 4px; border: 1px solid #26262a; background: #000000; color: #ffffff; font-family: monospace; font-size: 0.8rem; transition: 0.2s; }
  input:focus { border-color: #ffffff; outline: none; }

  .btn-action { width: 100%; padding: 0.75rem; border-radius: 4px; border: none; background: #ffffff; color: #000000; font-weight: 700; cursor: pointer; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1.5rem; transition: 0.2s; }
  .btn-action:hover { background: #d4d4d8; }

  .grid-loc { display: grid; grid-template-columns: 1fr; gap: 0.5rem; margin-bottom: 1.4rem; }
  .loc-card { background: #000000; border: 1px solid #222225; border-radius: 4px; padding: 0.75rem 0.85rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center; transition: 0.2s; }
  .loc-card:hover { border-color: #52525b; }
  .loc-card.active { border-color: #ffffff; background: #141416; }
  .loc-title { font-size: 0.8rem; font-weight: 600; color: #e4e4e7; font-family: inherit; }

  .selector { display: flex; background: #000000; border-radius: 4px; padding: 0.25rem; margin-bottom: 1.4rem; border: 1px solid #222225; }
  .s-btn { flex: 1; text-align: center; padding: 0.65rem 0.4rem; font-size: 0.78rem; font-weight: 600; border-radius: 3px; cursor: pointer; color: #71717a; transition: 0.2s; }
  .s-btn.active { background: #ffffff; color: #000000; }

  .qr-frame { background: #ffffff; padding: 0.8rem; border-radius: 4px; width: fit-content; margin: 0 auto 1.2rem auto; display: flex; justify-content: center; }
  .btn-copy { width: 100%; padding: 0.85rem; border-radius: 4px; border: 1px solid #ffffff; background: #ffffff; color: #000000; font-weight: 700; font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.05em; cursor: pointer; margin-bottom: 1.5rem; transition: 0.2s; }
  .btn-copy:hover { background: #000000; color: #ffffff; }

  .divider { border-top: 1px solid #222225; margin: 1.5rem 0; }
  .section-title { font-size: 0.75rem; font-weight: 700; color: #71717a; margin-bottom: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; }
</style>
</head>
<body>
<div class="box">
  <div class="top-bar">
    <div class="logo-tag">
      <h1>BERMUDA1998</h1>
      <span class="badge">CORE 3.0</span>
    </div>
    <a href="/logout" class="exit">DISCONNECT</a>
  </div>

  <form method="POST">
    <input type="hidden" name="action" value="save_connection">
    <label class="step-label">Step 1: Network TCP Endpoint</label>
    <input type="text" name="endpoint" value="{{ENDPOINT}}" placeholder="junction.proxy.rlwy.net:PORT" required autocomplete="off">
    <button type="submit" class="btn-action">Commit Network Config</button>
  </form>

  <label class="step-label">Step 2: Core Geolocation</label>
  <div class="grid-loc">
    <div class="loc-card active" id="loc0" onclick="selectLocation(0)">
      <span class="loc-title">NL • EU West (Amsterdam)</span>
    </div>
    <div class="loc-card" id="loc1" onclick="selectLocation(1)">
      <span class="loc-title">SG • Southeast Asia (Singapore)</span>
    </div>
    <div class="loc-card" id="loc2" onclick="selectLocation(2)">
      <span class="loc-title">US • US East (Virginia)</span>
    </div>
    <div class="loc-card" id="loc3" onclick="selectLocation(3)">
      <span class="loc-title">US • US West (California)</span>
    </div>
  </div>

  <label class="step-label">Step 3: Routing Policy</label>
  <div class="selector">
    <div class="s-btn active" id="btnStd" onclick="setMode('standard')">Standard Route</div>
    <div class="s-btn" id="btnAI" onclick="setMode('ai')">AI Dedicated</div>
  </div>

  <label class="step-label">Step 4: Transport Architecture</label>
  <div class="selector">
    <div class="s-btn active" id="btnWs" onclick="setTransport('ws')">WebSocket (Standard)</div>
    <div class="s-btn" id="btnXhttp" onclick="setTransport('xhttp')">XHTTP (Anti-DPI)</div>
  </div>

  <div class="qr-frame" id="qrcode"></div>
  <button class="btn-copy" onclick="copyConfig()">Export Config Link</button>

  <div class="divider"></div>
  <div class="section-title">Credentials & Access Control</div>
  <form method="POST">
    <input type="hidden" name="action" value="save_security">
    <label class="step-label">Update Operator ID</label>
    <input type="text" name="new_username" placeholder="New Operator ID" required autocomplete="off">
    <label class="step-label">Update Access Key</label>
    <input type="password" name="new_password" placeholder="New Access Key" required>
    <button type="submit" class="btn-action" style="background:#18181b;color:#e4e4e7;border:1px solid #27272a;margin-bottom:0;">Update Security State</button>
  </form>
</div>

<script>
  const locations = [
    "NL • EU West (Amsterdam)",
    "SG • Southeast Asia (Singapore)",
    "US • US East (Virginia)",
    "US • US West (California)"
  ];

  let currentMode = 'standard';
  let currentTransport = 'ws';
  let selectedIdx = 0;
  const idNormal = "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d";
  const idAI     = "f9e8d7c6-b5a4-3210-fedc-ba9876543210";
  const h = "{{HOST}}";
  const p = "{{PORT}}";
  let vlessURL = "";

  function setMode(mode) {
    currentMode = mode;
    document.getElementById('btnStd').classList.toggle('active', mode === 'standard');
    document.getElementById('btnAI').classList.toggle('active', mode === 'ai');
    render();
  }

  function setTransport(tp) {
    currentTransport = tp;
    document.getElementById('btnWs').classList.toggle('active', tp === 'ws');
    document.getElementById('btnXhttp').classList.toggle('active', tp === 'xhttp');
    render();
  }

  function selectLocation(idx) {
    selectedIdx = idx;
    for (let i = 0; i < locations.length; i++) {
      document.getElementById('loc' + i).classList.toggle('active', i === idx);
    }
    render();
  }

  function render() {
    if (!h || !p) {
      document.getElementById('qrcode').innerHTML = '<div style="color:#000;font-size:11px;font-family:monospace;padding:10px;">ENDPOINT UNCONFIGURED</div>';
      return;
    }
    
    let baseName = locations[selectedIdx];
    let modeSuffix = (currentMode === 'ai') ? " [AI]" : "";
    let tpSuffix = (currentTransport === 'xhttp') ? " (XHTTP)" : " (WS)";
    let finalName = baseName + modeSuffix + tpSuffix;
    let uid = (currentMode === 'ai') ? idAI : idNormal;

    if (currentTransport === 'xhttp') {
      vlessURL = 'vless://' + uid + '@' + h + ':' + p + '?type=xhttp&security=none&path=%2Fxhttp&mode=auto&encryption=none&packetEncoding=xudp#' + encodeURIComponent(finalName);
    } else {
      vlessURL = 'vless://' + uid + '@' + h + ':' + p + '?type=ws&security=none&path=%2F&encryption=none&packetEncoding=xudp#' + encodeURIComponent(finalName);
    }
    
    document.getElementById('qrcode').innerHTML = '';
    new QRCode(document.getElementById('qrcode'), {
      text: vlessURL,
      width: 180,
      height: 180,
      colorDark: "#000000",
      colorLight: "#ffffff",
      correctLevel: QRCode.CorrectLevel.M
    });
  }

  function copyConfig() {
    if(!vlessURL) return alert('Configure TCP endpoint first.');
    navigator.clipboard.writeText(vlessURL);
    alert('Config copied to clipboard.');
  }

  render();
</script>
</body>
</html>`
