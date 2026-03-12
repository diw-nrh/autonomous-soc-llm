"""
SOC Agent - my_autonomous-soc
ตัวแทนรปภ. AI ที่ฝังตัวในระบบจริง เพื่อวิเคราะห์ Log แบบ Real-time
"""
import sys
import os
import torch
import warnings
import logging
import threading

warnings.filterwarnings('ignore')
logging.getLogger("transformers").setLevel(logging.ERROR)

# เพิ่ม Path ให้เรียกใช้งาน engine จากโฟลเดอร์ research ได้
RESEARCH_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'soc_llm_research'))
sys.path.append(RESEARCH_DIR)

try:
    from engine.vector_store import SOCVectorStore
    from unsloth import FastLanguageModel
    import faiss
except ImportError:
    print("⚠️  โมดูลบางตัวหายไป กรุณาติดตั้ง unsloth, faiss-cpu, torch")

MODEL_ID = os.path.join(RESEARCH_DIR, "soc_security_model")
FAISS_INDEX = os.path.join(RESEARCH_DIR, "outputs", "soc_index.faiss")
FAISS_DATA = os.path.join(RESEARCH_DIR, "outputs", "soc_data.csv")

class SOCAgent:
    def __init__(self):
        self.alerts = []
        self.vector_store = None
        self.model = None
        self.tokenizer = None
        self.lock = threading.Lock()  # ตัวล็อคป้องกันเรียกใช้ AI พร้อมกัน
        
        self.setup_rag()
        self.setup_llm()

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
             print(f"⚠️  หาโฟลเดอร์โมเดล {MODEL_ID} ไม่เจอ! คุณอาจจะยังเทรนไม่เสร็จ หรือระบุพาธผิด")
             return

        try:
            self.model, self.tokenizer = FastLanguageModel.from_pretrained(
                model_name=MODEL_ID,
                max_seq_length=1024,
                dtype=None,
                load_in_4bit=True,
            )
            FastLanguageModel.for_inference(self.model)
            print("✅ AI SOC Analyst พร้อมทำงาน!")
        except Exception as e:
            print(f"⚠️  Model Load Error: {e}")

    def analyze_request(self, log_data: dict):
        """รับ Log 1 บรรทัด แล้วเอาไปให้ AI วิเคราะห์พร้อม RAG"""
        if not self.model:
            return

        # ป้องกันการแย่งกันใช้โมเดลบน GPU จากหลายๆ Thread พร้อมกัน
        with self.lock:
            # 1. จัด Format Log ให้เหมือนตอนเราเทรนมาเป๊ะๆ
            log_text = f"Method: {log_data.get('Method','')[:10]} | URL: {log_data.get('URL','')[:200]} | Content: {log_data.get('content','')[:200]} | UA: {log_data.get('User-Agent','')[:100]}"
            
            # 2. ค้นหาในประวัติ RAG ว่าเคยเจออะไรแบบนี้ไหม (ดึงมา 2 อันดับ)
            context = ""
        if self.vector_store and self.vector_store.index:
            try:
                similar_logs = self.vector_store.search_similar(log_text, k=2)
                if similar_logs:
                    context = "### REFERENCE FROM DATABASE:\n"
                    for i, item in enumerate(similar_logs):
                        lbl = "Normal (0)" if str(item['label']) == '0' else "Attack (1)"
                        context += f"- Past Case: {item['log']} | Result: {lbl}\n"
            except Exception as e:
                pass # ถ้า RAG พังก็วิเคราะห์ต่อไปแบบเพียวๆ

        # 3. เตรียมคำสั่ง Prompt เต็มขั้นให้ Llama 3.2
        prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>
You are an expert SOC analyst specialized in detecting API attacks (SQLi, XSS, XXE, RCE, Brute Force).
{context}
<|eot_id|><|start_header_id|>user<|end_header_id|>
### Task:
Analyze this API log for security threats. Is it malicious or normal traffic?
### Log/Input:
{log_text}<|eot_id|><|start_header_id|>assistant<|end_header_id|>
"""
        inputs = self.tokenizer(prompt, return_tensors="pt").to("cuda")
        
        # 4. ออกคำสั่งให้ AI เดาผล
        with torch.no_grad():
            outputs = self.model.generate(
                **inputs, 
                max_new_tokens=150,
                temperature=0.1,
                do_sample=True,
                pad_token_id=self.tokenizer.eos_token_id
            )
            
        response = self.tokenizer.decode(outputs[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        
        # 5. ตีความผลลัพธ์
        is_attack = "1" in response or "ATTACK" in response.upper() or "MALICIOUS" in response.upper() or "CRITICAL" in response.upper()
        
        if is_attack:
            alert = {
                "status": "ALERT",
                "target": log_data.get('URL', 'Unknown'),
                "method": log_data.get('Method', 'Unknown'),
                "analysis": response.strip()
            }
            self.alerts.append(alert)
            print("="*60)
            print(f"🚨 [SOC ALERT] ตรวจพบการโจมตี API!")
            print(f"🎯 เป้าหมาย: {log_data.get('URL')}")
            print(f"📝 สรุปจาก AI: \n{response.strip()}")
            print("="*60)
            
    def get_recent_alerts(self):
        """ดึงการแจ้งเตือน 10 ครั้งล่าสุด"""
        return self.alerts[-10:]
