"""
FastAPI Server หลักที่มีด่านตรวจ Middleware
สำหรับดักจับ Requests แล้วโยนให้ AI SOC Analyst วิเคราะห์แบบเป็น Background
(คุณสามารถใช้ Burp Suite ยิงโจมตีที่นี่ได้เลย)
"""
from fastapi import FastAPI, Request
from agent import SOCAgent
import json
import threading

app = FastAPI(title="🔒 API Endpoint Protected by Autonomous SOC")
 
# โหลดผู้ช่วย SOC ทำงานเตรียมรอไว้เลย
soc_agent = SOCAgent()
LOG_FILE = "api_attacks.jsonl"

def analyze_and_log(log_data: dict):
    """ฟังก์ชันทำงานเบื้องหลัง: เซฟ Log ลงไฟล์ และส่งให้ AI วิเคราะห์"""
    # 1. บันทึกเป็นไฟล์ (เผื่อทำ Dataset เทรนเพิ่มรอบหน้า)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_data) + "\n")
    
    # 2. ป้อนให้ AI วิเคราะห์
    soc_agent.analyze_request(log_data)


@app.middleware("http")
async def soc_middleware(request: Request, call_next):
    """
    ด่านตรวจ (Middleware): จะรวบรวมทุก Request (รวมถึงของ Burp Suite) 
    และแพ็กส่งไปให้ AI ทำงานตรวจสอบเบื้องหลัง (Background Thread)
    """
    # ระวังปัญหา: Request body ถ้าถูกอ่านไปรอบนึงแล้วจะอ่านอีกไม่ได้ใน FastAPI
    # เราจึงอ่านมันมาเก็บสแปร์ไว้ก่อน แล้วยัดคืนเข้าไป
    body_bytes = await request.body()
    body_str = body_bytes.decode('utf-8') if body_bytes else ""
    
    # แพ็กข้อมูลเหมือนที่เทรน
    log_data = {
        "Method": request.method,
        "URL": str(request.url),
        "content": body_str,
        "User-Agent": request.headers.get("user-agent", "")
    }

    # เพื่อไม่ให้ API ค้างรอ AI วิเคราะห์จน timeout เราจะใช้ Thread ยิงงานไปให้ AI ด้านหลัง
    threading.Thread(target=analyze_and_log, args=(log_data,)).start()
    
    # ให้ Request ตัวจริงผ่านเข้าไประบบปกติ
    response = await call_next(request)
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

if __name__ == "__main__":
    import uvicorn
    # รันเซิฟเวอร์ที่พอร์ต 8000
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
