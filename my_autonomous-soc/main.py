"""
FastAPI Server หลักที่มีด่านตรวจ Middleware
สำหรับดักจับ Requests แล้วโยนให้ AI SOC Analyst วิเคราะห์แบบเป็น Background
(คุณสามารถใช้ Burp Suite ยิงโจมตีที่นี่ได้เลย)
"""
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from agent import SOCAgent
import os

app = FastAPI(title="🔒 API Endpoint Protected by Autonomous SOC")
 
# โหลดผู้ช่วย SOC ทำงานเตรียมรอไว้เลย
soc_agent = SOCAgent()


@app.middleware("http")
async def soc_middleware(request: Request, call_next):
    """
    ด่านตรวจ (Middleware): จะรวบรวมทุก Request (รวมถึงของ Burp Suite) 
    และแพ็กส่งไปให้ AI ทำงานตรวจสอบเบื้องหลัง (Background Thread)
    """
    # === Whitelist: Path ที่ไม่ต้องวิเคราะห์ (Internal SOC & Dashboard paths) ===
    # เหตุผล: Dashboard polling /soc/dashboard ทุก 3 วิ ทำให้เกิด False Positive
    SKIP_PATHS = {"/", "/soc/alerts", "/soc/dashboard", "/soc/logs", "/soc/logs/csv", "/dashboard", "/docs", "/openapi.json", "/favicon.ico", "/robots.txt"}
    if request.url.path in SKIP_PATHS:
        return await call_next(request)

    body_bytes = await request.body()
    body_str = body_bytes.decode('utf-8') if body_bytes else ""
    
    log_data = {
        "Method": request.method,
        "URL": str(request.url),
        "content": body_str,
        "User-Agent": request.headers.get("user-agent", "")
    }
    
    response = await call_next(request)
    log_data["Status-Code"] = response.status_code

    # Queue Worker จะรับงานไปวิเคราะห์ใน Background (Non-blocking)
    soc_agent.analyze_request(log_data)
    
    # บังคับ close connection ทุก response → Burp Suite และ HTTP client ได้ผลทันที
    response.headers["Connection"] = "close"
    return response


# ==========================================
# 🎯 API Endpoints สำหรับให้คุณ Fuzz ด้วย Burp Suite
# ==========================================

@app.get("/")
def home():
    return {"message": "Welcome to Secure API. The SOC AI is watching."}

@app.get("/api/v1/search")
async def search_endpoint(q: str = ""):
    # Endpoint อ่อนแอ จำลองว่าอาจโดน SQLi (เช่น q=1' OR '1'='1)
    return {"status": "success", "results": f"Searching for {q}"}

@app.post("/api/v1/login")
async def login_endpoint(request: Request):
    # Endpoint จำลองสำหรับโดน XSS หรือ SQLi (เช่น POST body ยัด XML/XXE มา)
    body = await request.body()
    return {"status": "failed", "reason": "Invalid credentials"}

@app.get("/api/v1/download")
async def download_file(file: str = "report.pdf"):
    # Endpoint จำลองอาจโดน RCE/Path Traversal (เช่น file=../../../etc/passwd)
    return {"status": "success", "file": file}


# ==========================================
# 🛡️ SOC Dashboard Endpoint
# ==========================================
@app.get("/soc/alerts")
def get_soc_alerts():
    """แสดงการแจ้งเตือนจาก AI แบบเรียลไทม์"""
    return {
        "total_alerts": len(soc_agent.alerts),
        "recent_alerts": soc_agent.get_recent_alerts()
    }

@app.get("/soc/dashboard")
def get_dashboard_stats():
    """สถิติสำหรับ Dashboard อัพเดตทุก 3 วินาที"""
    return soc_agent.get_dashboard_stats()

@app.get("/soc/logs")
def get_recent_logs(limit: int = 50):
    """ดึง Log ล่าสุดสำหรับตาราง Live Feed"""
    return {"logs": soc_agent.all_logs[-limit:]}

@app.get("/soc/logs/csv")
def download_logs_csv():
    """Download log เป็นไฟล์ CSV"""
    csv_path = os.path.join(os.path.dirname(__file__), "soc_log.csv")
    if os.path.exists(csv_path):
        return FileResponse(csv_path, media_type='text/csv', filename='soc_attacks_log.csv')
    return {"error": "No log file found yet"}

@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    """หน้า SOC Dashboard UI"""
    html_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Dashboard not found</h1>")

if __name__ == "__main__":
    import uvicorn
    # reload=False เพื่อป้องกัน AI โหลดซ้ำทุกครั้งที่แก้ไฟล์ → OOM crash
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
