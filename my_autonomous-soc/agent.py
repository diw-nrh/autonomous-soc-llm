"""
SOC Agent - my_autonomous-soc
ตัวแทนรปภ. AI ที่ฝังตัวในระบบจริง เพื่อวิเคราะห์ Log แบบ Real-time
สถาปัตยกรรม: Queue Worker Pattern → Thread-safe + Unsloth Fast Inference ✅
"""
import sys
import os
import csv
import queue
import torch
import warnings
import logging
import threading
from datetime import datetime

warnings.filterwarnings('ignore')
logging.getLogger("transformers").setLevel(logging.ERROR)

# เพิ่ม Path ให้เรียกใช้งาน engine จากโฟลเดอร์ research ได้
RESEARCH_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'soc_llm_research'))
sys.path.append(RESEARCH_DIR)

try:
    from engine.vector_store import SOCVectorStore
    from unsloth import FastLanguageModel
except ImportError:
    print("⚠️  โมดูลบางตัวหายไป กรุณาติดตั้ง unsloth, faiss-cpu, torch")

MODEL_ID = os.path.join(RESEARCH_DIR, "soc_security_model")
FAISS_INDEX = os.path.join(RESEARCH_DIR, "outputs", "soc_index.faiss")
FAISS_DATA = os.path.join(RESEARCH_DIR, "outputs", "soc_data.csv")
LOG_CSV_PATH = "soc_log.csv"

def _ensure_csv_header():
    """สร้างไฟล์ CSV และหัวตารางถ้ายังไม่มี"""
    if not os.path.exists(LOG_CSV_PATH):
        with open(LOG_CSV_PATH, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "method", "url", "user_agent", "status", "attack_type", "ai_analysis"])

def _detect_attack_type(url: str, content: str, ai_response: str) -> str:
    """ตรวจจับประเภทการโจมตีจาก URL, Content และคำตอบของ AI (พร้อมระบบกัน False Positive)"""
    resp_upper = ai_response.upper()
    
    # หรือถ้า AI บอกชัดเจนว่าปกติ ไม่ต้องพยายามหา Keyword การโจมตี
    if "NORMAL" in resp_upper or "NO ATTACK" in resp_upper or "LEGITIMATE" in resp_upper:
        return "Normal"

    text = (url + " " + content + " " + ai_response).upper()
    
    # 1. Path Traversal / LFI (ตรวจสอบก่อนเพราะมักจะโดนไปรวมกับ XXE/RCE)
    if "/ETC/PASSWD" in text or "../" in url or "..%2F" in url or "TRAVERSAL" in resp_upper:
        return "Path Traversal"

    # 2. SQL Injection
    if "SQLI" in text or "SQL INJECTION" in text or "UNION SELECT" in text or "OR 1=1" in text or "%27" in url:
        return "SQLi"
    
    # 3. XML External Entity (XXE)
    elif "XXE" in text or "XML EXTERNAL" in text or "DOCTYPE" in text or "ENTITY" in text:
        return "XXE"
    
    # 4. Cross-Site Scripting (XSS)
    elif "XSS" in text or "CROSS-SITE" in text or "<SCRIPT" in text.replace("%3C","<"):
        return "XSS"
    
    # 5. Remote Code Execution (RCE) / Suspect
    elif "RCE" in text or "COMMAND INJECTION" in text or "REMOTE CODE" in text:
        return "RCE"
    
    elif "ATTACK" in text or "MALICIOUS" in text or "INJECTION" in text:
        return "Other Attack"
    
    return "Normal"


class SOCAgent:
    def __init__(self):
        self.alerts = []
        self.all_logs = []          # เก็บ log ทั้งหมดสำหรับ Dashboard
        self.vector_store = None
        self.model = None
        self.tokenizer = None

        # === Queue Worker Pattern ===
        # maxsize=500 ป้องกัน Memory Leak ถ้าถูก Fuzz เร็วกว่า AI วิเคราะห์ได้
        self.request_queue = queue.Queue(maxsize=500)
        # Lock ป้องกัน Race Condition บน all_logs / alerts (FastAPI อ่าน + Worker เขียนพร้อมกัน)
        self.data_lock = threading.Lock()
        _ensure_csv_header()

        self.setup_rag()
        self.setup_llm()

        # เริ่ม Worker Thread background (daemon=True → ปิดตามเซิร์ฟเวอร์อัตโนมัติ)
        self._worker_thread = threading.Thread(target=self._inference_worker, daemon=True)
        self._worker_thread.start()
        print("🔄 Queue Worker Thread เริ่มทำงานแล้ว!")

    def setup_rag(self):
        """โหลดข้อมูลอดีต (Past Cases) จาก FAISS Index"""
        print("📚 กำลังเชื่อมต่อระบบ RAG (FAISS Index)...")
        try:
            self.vector_store = SOCVectorStore()
            if self.vector_store.load_index(index_path=FAISS_INDEX, data_path=FAISS_DATA):
                print("✅ ระบบ RAG พร้อมใช้งาน")
            else:
                print("⚠️  หาไฟล์ RAG FAISS ไม่เจอ (แต่ยังทำงานต่อได้แบบไม่มีความรู้เก่า)")
        except Exception as e:
            print(f"⚠️  RAG Setup Error: {e}")

    def setup_llm(self):
        """โหลดโมเดลที่ Fine-tune มาด้วยแบบกินแรมน้อยสุด (4-bit)"""
        print("🤖 กำลังปลุก AI SOC Analyst...")
        if not os.path.exists(MODEL_ID):
             print(f"⚠️  หาโฟลเดอร์โมเดล {MODEL_ID} ไม่เจอ!")
             return

        try:
            self.model, self.tokenizer = FastLanguageModel.from_pretrained(
                model_name=MODEL_ID,
                max_seq_length=1024,
                dtype=None,
                load_in_4bit=True,
            )
            # ✅ กลับมาใช้ Unsloth Fast Inference ได้อีกครั้ง
            # เพราะ Queue Worker ทำให้ GPU ถูกใช้จาก Thread เดียวเท่านั้น
            FastLanguageModel.for_inference(self.model)
            print("✅ AI SOC Analyst พร้อมทำงาน! (Unsloth Fast Inference + Queue Worker 🚀)")
        except Exception as e:
            print(f"⚠️  Model Load Error: {e}")

    # =========================================================
    # QUEUE WORKER: ทำงานใน Background Thread เดียว
    # รับงานจาก Queue ทีละ 1 — ปลอดภัยกับ Unsloth Fast Inference
    # =========================================================
    def _inference_worker(self):
        """Worker loop — รันตลอดชีวิตของเซิร์ฟเวอร์"""
        print("✅ Inference Worker พร้อมรับงานจาก Queue แล้ว")
        while True:
            try:
                # ดึงงานจาก Queue (block=True → รอจนกว่าจะมีงาน)
                log_data = self.request_queue.get(block=True, timeout=1)
                self._run_inference(log_data)
                self.request_queue.task_done()
            except queue.Empty:
                continue  # ไม่มีงานในคิว → วนรอต่อ
            except Exception as e:
                print(f"⚠️  Worker Error: {e}")

    def _run_inference(self, log_data: dict):
        """ตัว inference จริงๆ — ทำงานใน Worker Thread เดียวเสมอ"""
        if not self.model:
            return

        # 1. จัด Format Log
        log_text = (
            f"Method: {log_data.get('Method','')[:10]} | "
            f"URL: {log_data.get('URL','')[:200]} | "
            f"Content: {log_data.get('content','')[:200]} | "
            f"UA: {log_data.get('User-Agent','')[:100]}"
        )

        # 2. RAG Search
        context = ""
        if self.vector_store and self.vector_store.index:
            try:
                similar_logs = self.vector_store.search_similar(log_text, k=2)
                if similar_logs:
                    context = "### REFERENCE FROM DATABASE:\n"
                    for item in similar_logs:
                        lbl = "Normal (0)" if str(item['label']) == '0' else "Attack (1)"
                        context += f"- Past Case: {item['log']} | Result: {lbl}\n"
            except Exception:
                pass

        # 3. Prompt - ปรับปรุงให้ AI ตอบละเอียดขึ้นตามที่เทรนมา
        system_prompt = """You are an expert SOC (Security Operations Center) analyst specialized in:
- SQL Injection (SQLi) detection: classic, blind, UNION-based, error-based, time-based, stacked queries
- XXE (XML External Entity) injection detection: file disclosure, SSRF, OOB, DoS
- XSS (Cross-Site Scripting) detection: reflected, stored, DOM-based, obfuscated
- Remote Code Execution (RCE) and Command Injection detection
- Path Traversal and Local File Inclusion (LFI) detection
- OWASP Top 10 threat identification

Analyze logs with precision. Always provide: attack classification, severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), technical explanation, IoCs, and remediation steps.
RULES:
1. If the log is harmless traffic, respond with "Normal traffic" and nothing else.
2. If an attack is detected, you MUST provide a detailed security analysis report.
3. Distinguish between XXE and Path Traversal. /etc/passwd is Path Traversal.
"""
        prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>
{system_prompt}
{context}<|eot_id|><|start_header_id|>user<|end_header_id|>
### Task:
Analyze this API log:
{log_text}<|eot_id|><|start_header_id|>assistant<|end_header_id|>
"""
        # 4. Inference (Unsloth Fast Mode — ปลอดภัยเพราะ Thread เดียว)
        try:
            inputs = self.tokenizer(prompt, return_tensors="pt").to("cuda")
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=300,
                    do_sample=True,
                    temperature=0.1,
                    pad_token_id=self.tokenizer.eos_token_id,
                    repetition_penalty=1.1,
                )
            response = self.tokenizer.decode(
                outputs[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True
            )
        except Exception as e:
            print(f"⚠️  Inference Error: {e}")
            return

        # 5. จำแนกผลลัพธ์ — ใช้ระบบตรวจจับที่รัดกุมขึ้น
        resp_upper = response.upper()
        # ถ้ามีคำว่า ATTACK / MALICIOUS / CRITICAL และไม่มีคำว่า NORMAL/NO ATTACK ปนอยู่
        is_attack = (
            ("ATTACK" in resp_upper or "MALICIOUS" in resp_upper or "CRITICAL" in resp_upper) and
            ("NORMAL" not in resp_upper and "NO ATTACK" not in resp_upper)
        ) or "LABEL: 1" in resp_upper or "VERDICT: 1" in resp_upper
        attack_type = _detect_attack_type(
            log_data.get('URL', ''), log_data.get('content', ''), response
        ) if is_attack else "Normal"

        # 6. บันทึกลง CSV
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_CSV_PATH, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                timestamp, log_data.get('Method', ''),
                log_data.get('URL', '')[:300],
                log_data.get('User-Agent', '')[:100],
                "ALERT" if is_attack else "Normal",
                attack_type, response.strip()[:500]
            ])

        # 7. เก็บใน memory สำหรับ Dashboard (Thread-safe)
        log_entry = {
            "timestamp": timestamp,
            "method": log_data.get('Method', ''),
            "url": log_data.get('URL', '')[:200],
            "status": "ALERT" if is_attack else "Normal",
            "attack_type": attack_type,
            "ai_analysis": response.strip()[:500]
        }
        with self.data_lock:
            self.all_logs.append(log_entry)
            if len(self.all_logs) > 200:
                self.all_logs = self.all_logs[-200:]

        if is_attack:
            with self.data_lock:
                self.alerts.append({
                    "timestamp": timestamp, "status": "ALERT",
                    "target": log_data.get('URL', 'Unknown'),
                    "method": log_data.get('Method', 'Unknown'),
                    "attack_type": attack_type, "analysis": response.strip()
                })
            print("="*60)
            print(f"🚨 [SOC ALERT] ตรวจพบการโจมตี API! [{attack_type}]")
            print(f"🎯 เป้าหมาย: {log_data.get('URL')}")
            print(f"📝 สรุปจาก AI: \n{response.strip()}")
            print("="*60)

    # =========================================================
    # PUBLIC API — เรียกจาก main.py Middleware
    # =========================================================
    def analyze_request(self, log_data: dict):
        """ใส่งานเข้าคิว → Worker จะจัดการเอง (Non-blocking)"""
        self.request_queue.put(log_data)

    def get_recent_alerts(self):
        """ดึงการแจ้งเตือน 10 ครั้งล่าสุด"""
        return self.alerts[-10:]

    def get_dashboard_stats(self): 
        """สรุปสถิติสำหรับ Dashboard"""
        total = len(self.all_logs)
        attacks = [l for l in self.all_logs if l['status'] == 'ALERT']
        attack_types = {"Normal": total - len(attacks)}
        for a in attacks:
            t = a.get('attack_type', 'Unknown')
            attack_types[t] = attack_types.get(t, 0) + 1
        
        return {
            "total_requests": total,
            "total_attacks": len(attacks),
            "total_normal": total - len(attacks),
            "attack_types": attack_types,
            "recent_logs": self.all_logs[-50:]
        }
