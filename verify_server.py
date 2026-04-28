from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

NODE_IP = "202.189.9.12"
BRAND_NAME = "FengDu Security"


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_client_ip(request: Request) -> str:
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()

    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    return request.client.host if request.client else ""


@app.get("/ping")
def ping(request: Request):
    ip = get_client_ip(request)
    return {
        "success": True,
        "ip": ip,
        "node_ip": NODE_IP,
        "connected": ip == NODE_IP,
    }


@app.get("/", response_class=HTMLResponse)
@app.get("/verify", response_class=HTMLResponse)
def verify(request: Request):
    ip = get_client_ip(request)
    ok = ip == NODE_IP

    status_text = "节点已连接" if ok else "未通过节点"
    status_icon = "✅" if ok else "✕"
    status_class = "online" if ok else "offline"
    tip = (
        "当前访问已通过 FengDu 节点，防护状态正常。"
        if ok
        else "请先开启 Shadowrocket，并选择 FengDu 节点后重新检测。"
    )

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>风度安全 · 节点防护验证</title>
<style>
* {{
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}}

:root {{
  --bg: #060b18;
  --surface: rgba(12, 18, 32, 0.92);
  --surface2: rgba(255,255,255,0.045);
  --border: rgba(0,240,255,0.16);
  --accent: #00F0FF;
  --purple: #8B5CF6;
  --text: #e8f4ff;
  --text-dim: rgba(232,244,255,0.52);
  --red: #ff6464;
  --green: #00F0FF;
}}

body {{
  min-height: 100vh;
  min-height: 100dvh;
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Microsoft YaHei", sans-serif;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: max(22px, env(safe-area-inset-top)) 18px max(22px, env(safe-area-inset-bottom));
  position: relative;
  overflow: hidden;
}}

body::before {{
  content: "";
  position: fixed;
  inset: 0;
  background-image:
    linear-gradient(rgba(0,240,255,0.028) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,240,255,0.028) 1px, transparent 1px);
  background-size: 48px 48px;
  pointer-events: none;
}}

body::after {{
  content: "";
  position: fixed;
  width: 520px;
  height: 520px;
  right: -190px;
  top: -180px;
  background: radial-gradient(circle, rgba(0,240,255,0.13), transparent 66%);
  pointer-events: none;
}}

.glow-left {{
  position: fixed;
  width: 480px;
  height: 480px;
  left: -190px;
  bottom: -210px;
  background: radial-gradient(circle, rgba(139,92,246,0.14), transparent 68%);
  pointer-events: none;
}}

.wrap {{
  width: 100%;
  max-width: 460px;
  position: relative;
  z-index: 1;
}}

.brand {{
  text-align: center;
  margin-bottom: 16px;
}}

.brand-icon {{
  width: 58px;
  height: 58px;
  margin: 0 auto 12px;
  border-radius: 17px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, rgba(0,240,255,0.14), rgba(139,92,246,0.24));
  border: 1px solid rgba(0,240,255,0.32);
  box-shadow: 0 0 28px rgba(0,240,255,0.18);
  font-size: 28px;
}}

.brand-title {{
  font-size: 18px;
  font-weight: 900;
  letter-spacing: 0.08em;
}}

.brand-title span {{
  color: var(--accent);
}}

.brand-sub {{
  margin-top: 5px;
  font-size: 11px;
  letter-spacing: 0.22em;
  color: rgba(255,255,255,0.24);
  text-transform: uppercase;
}}

.card {{
  width: 100%;
  background: var(--surface);
  border: 1px solid {"rgba(0,240,255,0.35)" if ok else "rgba(255,100,100,0.28)"};
  border-radius: 24px;
  padding: 28px 22px 24px;
  text-align: center;
  box-shadow:
    0 28px 80px rgba(0,0,0,0.46),
    0 0 0 1px rgba(255,255,255,0.035) inset,
    0 0 45px rgba(0,240,255,0.04) inset;
  backdrop-filter: blur(18px);
}}

.status-badge {{
  width: 82px;
  height: 82px;
  margin: 0 auto 18px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  background: {"rgba(0,240,255,0.08)" if ok else "rgba(255,100,100,0.07)"};
  border: 1px solid {"rgba(0,240,255,0.32)" if ok else "rgba(255,100,100,0.25)"};
  box-shadow: 0 0 28px {"rgba(0,240,255,0.16)" if ok else "rgba(255,100,100,0.12)"};
  font-size: 38px;
  font-weight: 900;
  color: {"#00F0FF" if ok else "#ff6464"};
}}

.status-title {{
  font-size: 30px;
  line-height: 1.2;
  font-weight: 950;
  letter-spacing: 0.04em;
  color: {"#00F0FF" if ok else "#ff6464"};
  text-shadow: 0 0 24px {"rgba(0,240,255,0.34)" if ok else "rgba(255,100,100,0.20)"};
  margin-bottom: 20px;
}}

.info-box {{
  display: grid;
  gap: 12px;
  margin-top: 18px;
}}

.info-row {{
  background: rgba(255,255,255,0.045);
  border: 1px solid rgba(255,255,255,0.075);
  border-radius: 14px;
  padding: 13px 14px;
}}

.info-label {{
  font-size: 12px;
  letter-spacing: 0.12em;
  color: rgba(232,244,255,0.42);
  margin-bottom: 6px;
}}

.info-value {{
  color: #e8f4ff;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 18px;
  font-weight: 750;
  word-break: break-all;
}}

.info-value.accent {{
  color: var(--accent);
}}

.tip {{
  margin-top: 20px;
  padding: 14px 15px;
  color: rgba(0,240,255,0.72);
  font-size: 14px;
  line-height: 1.7;
  background: linear-gradient(135deg, rgba(0,240,255,0.055), rgba(139,92,246,0.06));
  border: 1px solid rgba(0,240,255,0.14);
  border-left: 3px solid var(--accent);
  border-radius: 12px;
}}

.tip.offline {{
  color: rgba(255,190,190,0.8);
  background: rgba(255,100,100,0.06);
  border-color: rgba(255,100,100,0.18);
  border-left-color: var(--red);
}}

.actions {{
  margin-top: 20px;
  display: grid;
  grid-template-columns: 1fr;
  gap: 10px;
}}

.btn {{
  display: block;
  width: 100%;
  padding: 13px 14px;
  border-radius: 14px;
  color: #fff;
  text-decoration: none;
  font-size: 15px;
  font-weight: 850;
  letter-spacing: 0.05em;
  background: linear-gradient(135deg, #00c8d8, #8B5CF6);
  box-shadow:
    0 0 0 1px rgba(255,255,255,0.08) inset,
    0 12px 32px rgba(0,200,216,0.22),
    0 0 32px rgba(139,92,246,0.18);
}}

.btn-secondary {{
  background: rgba(255,255,255,0.045);
  color: rgba(232,244,255,0.72);
  border: 1px solid rgba(255,255,255,0.09);
  box-shadow: none;
}}

.footer {{
  text-align: center;
  margin-top: 18px;
  color: rgba(255,255,255,0.18);
  font-size: 12px;
  letter-spacing: 0.08em;
}}

@media (max-width: 420px) {{
  .status-title {{
    font-size: 27px;
  }}
  .card {{
    padding: 25px 18px 22px;
  }}
}}
</style>
</head>

<body>
  <div class="glow-left"></div>

  <main class="wrap">
    <section class="brand">
      <div class="brand-icon">🛡️</div>
      <div class="brand-title"><span>风度安全</span> · 节点验证</div>
      <div class="brand-sub">FengDu Security Node Check</div>
    </section>

    <section class="card">
      <div class="status-badge {status_class}">{status_icon}</div>
      <div class="status-title">{status_text}</div>

      <div class="info-box">
        <div class="info-row">
          <div class="info-label">当前来源 IP</div>
          <div class="info-value {"accent" if ok else ""}">{ip}</div>
        </div>

        <div class="info-row">
          <div class="info-label">目标节点 IP</div>
          <div class="info-value accent">{NODE_IP}</div>
        </div>
      </div>

      <div class="tip {"offline" if not ok else ""}">{tip}</div>

      <div class="actions">
        <a class="btn" href=" ">查看 JSON 检测结果</a >
        <a class="btn btn-secondary" href="/verify">重新检测</a >
      </div>
    </section>

    <div class="footer">{BRAND_NAME} · Node Check</div>
  </main>
</body>
</html>"""