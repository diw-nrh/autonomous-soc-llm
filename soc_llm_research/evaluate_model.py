"""
📊 SOC Security Model Evaluation Script
สคริปต์วัดผล Accuracy, Precision, Recall บนข้อมูล test_data.jsonl
(ออกแบบมาเพื่อรันบน VRAM 4GB RTX 3050 Ti โดยเฉพาะ)
"""

import json
import torch
import numpy as np
import time
from tqdm import tqdm
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report
from unsloth import FastLanguageModel

# ===== CONFIG =====
MODEL_PATH = "soc_security_model" # โฟลเดอร์ที่เซฟเทรนเสร็จ
TEST_DATA_PATH = "data/test_data.jsonl"
MAX_SEQ_LENGTH = 1024
MAX_TEST_SAMPLES = 500 # จำกัดจำนวนข้อเพื่อไม่ให้กินเวลานานเกินไป (>1ชม.)

SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst specialized in:
- SQL Injection (SQLi) detection: classic, blind, UNION-based, error-based, time-based, stacked queries
- XXE (XML External Entity) injection detection: file disclosure, SSRF, OOB, DoS
- XSS (Cross-Site Scripting) detection: reflected, stored, DOM-based, obfuscated
- Remote Code Execution (RCE) and Command Injection detection
- Path Traversal and Local File Inclusion (LFI) detection
- OWASP Top 10 threat identification

Analyze logs with precision. Always provide: attack classification, severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), technical explanation, IoCs, and remediation steps."""

def load_test_data(filepath, max_samples=None):
    print(f"📂 กำลังโหลดข้อมูลทดสอบจาก: {filepath}")
    data = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                data.append(json.loads(line))
    except FileNotFoundError:
        print(f"❌ ไม่พบไฟล์ {filepath} โปรดรัน prepare_dataset.py ก่อนเพื่อสร้างไฟล์นี้")
        exit()
        
    print(f"📊 พบข้อมูลทั้งหมด: {len(data)} รายการ")
    if max_samples and len(data) > max_samples:
        # สุ่มตัวอย่างเพื่อให้ประเมินผลได้เร็วขึ้น
        import random
        random.seed(42)
        data = random.sample(data, max_samples)
        print(f"⏳ สุ่มดึงมาทดสอบจำนวน {max_samples} รายการเพื่อความรวดเร็ว...")
    
    return data

def main():
    # 1. โหลดโมเดลด้วย 4-bit quantization เพื่อประหยัด VRAM สูงสุด
    print("\n🤖 กำลังโหลดโมเดลสำหรับการวัดผล (พยายามใช้ VRAM น้อยสุดด้วย Unsloth)...")
    try:
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=MODEL_PATH,
            max_seq_length=MAX_SEQ_LENGTH,
            dtype=None,
            load_in_4bit=True,
        )
        FastLanguageModel.for_inference(model) # เปิดโหมดลด VRAM สูงสุด
    except Exception as e:
        print(f"❌ โหลดโมเดลไม่ได้: {e}")
        print("💡 สาเหตุอาจเป็นเพราะโมเดลยังไม่ถูกเทรนและบันทึก หรือหาไฟล์ไม่เจอ")
        return

    test_data = load_test_data(TEST_DATA_PATH, max_samples=MAX_TEST_SAMPLES)
    if not test_data:
        return

    y_true = []
    y_pred = []

    print("\n🚀 เริ่มต้นการประเมินผล (Evaluation)...")
    start_time = time.time()
    
    for i, item in tqdm(enumerate(test_data), total=len(test_data), desc="Evaluating Logs"):
        instruction = item.get("instruction", "")
        inp = item.get("input", "")
        expected_output = item.get("output", "")
        
        # ค้นหาว่าเป็น Class ไหน (ปกติ 0 หรือ โจมตี 1)
        # เนื่องจาก Output ใน Dataset User คือ "0" หรือ "1"
        is_attack_expected = "1" in expected_output
        y_true.append(1 if is_attack_expected else 0)

        prompt = (
            f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
            f"{SYSTEM_PROMPT}<|eot_id|>"
            f"<|start_header_id|>user<|end_header_id|>\n\n"
            f"### Task:\n{instruction}\n\n### Log/Input:\n{inp}<|eot_id|>"
            f"<|start_header_id|>assistant<|end_header_id|>\n\n"
        )

        inputs = tokenizer(prompt, return_tensors="pt").to("cuda")
        
        with torch.no_grad():
            outputs = model.generate(
                **inputs, 
                max_new_tokens=100, # ไม่ต้อง gen ยาวมาก เอาแค่ได้ผลสรุป
                temperature=0.1,    # ใช้ temp ต่ำเพื่อให้ได้ผลซ้ำๆ คงเดิม
                do_sample=True,
                pad_token_id=tokenizer.eos_token_id
            )
            
        # เคลียร์ Memory ระหว่าง Loop ทันที (VRAM 4GB ต้องประหยัด)
        if i % 10 == 0:
            torch.cuda.empty_cache()

        # ตัด prompt ออกเอาเฉพาะ response
        response = tokenizer.decode(outputs[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        
        # วิเคราะห์ผลที่ได้: หาก AI พิมพ์ "1", แดง, Attack หรืออะไรก็ตามที่ส่อถึงโจมตี
        is_attack_predicted = "1" in response or "ATTACK" in response.upper() or "MALICIOUS" in response.upper() or "CRITICAL" in response.upper() or "HIGH" in response.upper()
        
        y_pred.append(1 if is_attack_predicted else 0)

    end_time = time.time()
    elapsed_mins = (end_time - start_time) / 60

    # 4. คำนวณ Metrics วิจัย
    acc = accuracy_score(y_true, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary')
    
    print("\n" + "="*50)
    print(f"📊 รายงานผลการทดสอบ: Autonomous SOC LLM (VRAM Optimized)")
    print(f"⏱️ เวลาที่ใช้ทดสอบ: {elapsed_mins:.2f} นาที")
    print("="*50)
    
    print(f"📈 Accuracy  : {acc*100:.2f}% (เป้าหมาย: >80%)")
    print(f"🎯 Precision : {precision*100:.2f}% (ความแม่นยำเมื่อเตือนว่าโจมตี)")
    print(f"🔍 Recall    : {recall*100:.2f}% (ความครอบคลุมในการจับการโจมตี)")
    print(f"⚖️ F1-Score  : {f1*100:.2f}%\n")

    print("[Confusion Matrix]")
    cm = confusion_matrix(y_true, y_pred)
    print(f"True Negatives  (0->0): {cm[0][0]}")
    print(f"False Positives (0->1): {cm[0][1]}")
    print(f"False Negatives (1->0): {cm[1][0]}")
    print(f"True Positives  (1->1): {cm[1][1]}")
    
    print("\n[Classification Report]")
    print(classification_report(y_true, y_pred, target_names=["Normal (0)", "Attack (1)"]))

if __name__ == "__main__":
    main()
