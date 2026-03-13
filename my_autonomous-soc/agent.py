"""
SOC Agent — Merged v1 + v2
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
สิ่งที่เอามาจาก v2 (โครงสร้าง):
  PayloadNormalizer  — class แยกสะอาด, test ได้ง่าย
  HeuristicEngine    — Pattern dict + Auth_Abuse pattern
  RiskLevel enum     — อ่านง่ายกว่า bool/str
  _run_pipeline()    — แยก Stage 1 / Stage 2 ชัดเจน
  False Positive detection (BENIGN / FALSE POSITIVE)
  _sanitize_prompt_tokens() — ป้องกัน Prompt Injection

สิ่งที่เอามาจาก v1 (ความสามารถ):
  Layer 2: Entropy / Obfuscation detection
  Layer 3: Stateful Behavior (rate, error-burst, path-scan per IP)
  Layer 4: Random Sampling 5%
  filter_layer + filter_reason บันทึกลง CSV สำหรับ debug
  pipeline_stats แบบละเอียดใน dashboard

ลำดับการทำงาน:
  Normalize → Layer1 Regex → Layer2 Entropy
  → Layer3 Behavior → Layer4 Sample → Safe (skip LLM)
  ถ้าผ่านชั้นใด → ส่ง LLM → False Positive? → Confirmed Alert
"""

import sys
import os
import re
import csv
import math
import time
import queue
import random
import torch
import base64
import urllib.parse
import warnings
import logging
import threading
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional

warnings.filterwarnings("ignore")
logging.getLogger("transformers").setLevel(logging.ERROR)

RESEARCH_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "soc_llm_research"))
sys.path.append(RESEARCH_DIR)

try:
    from engine.vector_store import SOCVectorStore
    from unsloth import FastLanguageModel
except ImportError:
    print("⚠️  โมดูลบางตัวหายไป กรุณาติดตั้ง unsloth, faiss-cpu, torch")

MODEL_ID    = os.path.join(RESEARCH_DIR, "soc_security_model")
FAISS_INDEX = os.path.join(RESEARCH_DIR, "outputs", "soc_index.faiss")
FAISS_DATA  = os.path.join(RESEARCH_DIR, "outputs", "soc_data.csv")
LOG_CSV_PATH = "soc_log.csv"


# ══════════════════════════════════════════════════════════════
#  DATA CLASSES & ENUMS
# ══════════════════════════════════════════════════════════════

class RiskLevel(Enum):
    SAFE       = "Safe"       # ผ่านทุก Layer — ไม่ส่ง LLM
    SUSPICIOUS = "Suspicious" # Layer ใด Layer หนึ่งตั้งธง — รอ LLM
    CONFIRMED  = "Confirmed"  # LLM ยืนยัน — แจ้งเตือน


@dataclass
class FilterResult:
    """รวมผลจากทั้ง Heuristic + Entropy + Behavior + Sampling"""
    risk_level:       RiskLevel
    matched_tags:     list        # เช่น ["SQLi", "XSS"]
    layer:            int         # 0=safe, 1=regex, 2=entropy, 3=behavior, 4=sample
    reason:           str         # อธิบายว่าทำไมถึงตั้งธง
    normalized_url:   str
    normalized_content: str
    entropy_score:    float = 0.0


# ══════════════════════════════════════════════════════════════
#  STAGE 1-A: PAYLOAD NORMALIZER   (จาก v2 — สะอาดกว่า v1)
# ══════════════════════════════════════════════════════════════

class PayloadNormalizer:
    """
    ทำลายกลเม็ดหลบ Regex ของแฮกเกอร์ก่อนส่งตรวจ
    S-E-L-E-C-T / %53%45%4C / &#x53; → SELECT
    """

    def normalize(self, text: str) -> str:
        result = text

        # 1. URL Decode ซ้ำ 2 รอบ (จับ double-encoding)
        for _ in range(2):
            decoded = urllib.parse.unquote_plus(result)
            if decoded == result:
                break
            result = decoded

        # 2. HTML Entity Decode  &#x3c; → <  / &#60; → <
        result = re.sub(r"&#[xX]([0-9a-fA-F]+);?", lambda m: chr(int(m.group(1), 16)), result)
        result = re.sub(r"&#(\d+);?",               lambda m: chr(int(m.group(1))),     result)
        for entity, char in {"&lt;":"<","&gt;":">","&amp;":"&","&quot;":'"',"&#39;":"'"}.items():
            result = result.replace(entity, char)

        # 3. Hex literal  0x53454c454354 → SELECT
        result = re.sub(
            r"0x([0-9a-fA-F]{4,})",
            lambda m: self._decode_hex(m.group(1)),
            result, flags=re.IGNORECASE
        )

        # 4. JS \x escape  \x53\x45\x4c → SEL
        result = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), result)

        # 5. Base64 blob ยาวๆ
        result = re.sub(r"[A-Za-z0-9+/]{20,}={0,2}", lambda m: self._try_b64(m.group(0)), result)

        # 6. SQL/inline comment  /*!...*/ / -- comment / # comment
        result = re.sub(r"/\*!?.*?\*/", " ", result)
        result = re.sub(r"--[^\n]*",    " ", result)
        result = re.sub(r"#[^\n]*",     " ", result)

        # 7. ลบอักขระขยะระหว่างตัวอักษร  S-E-L-E-C-T → SELECT
        result = re.sub(r"(?<=[A-Za-z])[\s\-_\.\+/*]+(?=[A-Za-z])", "", result)

        return result.lower()

    @staticmethod
    def _decode_hex(hex_str: str) -> str:
        try:
            return bytes.fromhex(hex_str).decode("utf-8", errors="replace")
        except Exception:
            return hex_str

    @staticmethod
    def _try_b64(s: str) -> str:
        try:
            decoded = base64.b64decode(s + "==").decode("utf-8", errors="ignore")
            if re.search(r"[a-zA-Z]{3,}", decoded):
                return decoded
        except Exception:
            pass
        return s


# ══════════════════════════════════════════════════════════════
#  STAGE 1-B: HEURISTIC ENGINE — LAYER 1   (v2 patterns + v2 Auth_Abuse)
# ══════════════════════════════════════════════════════════════

class HeuristicEngine:
    """
    Layer 1: Regex กรองด้วย Pattern ที่รู้จัก
    ผลลัพธ์ SAFE → ส่งไป Layer 2 / SUSPICIOUS → ส่งให้ LLM
    """

    PATTERNS: dict = {

        "SQLi": re.compile(
            r"(\bunion\b.{0,30}\bselect\b"
            r"|\bselect\b.{0,30}\bfrom\b"
            r"|\bdrop\b\s+\btable\b"
            r"|\binsert\b\s+\binto\b"
            r"|\bdelete\b\s+\bfrom\b"
            r"|or\s+1\s*=\s*1"
            r"|'\s*or\s*'[^']*'\s*=\s*'"
            r"|--\s*$"
            r"|\band\s+1\s*=\s*['\"]?1['\"]?"
            r"|\bsleep\s*\(\d+\)"
            r"|\bwaitfor\s+delay\b"
            r"|\bxp_cmdshell\b"
            r"|\bbenchmark\s*\()",
            re.IGNORECASE,
        ),

        "XSS": re.compile(
            r"(<script[\s>]"
            r"|<\/script>"
            r"|javascript\s*:"
            r"|on(load|error|click|mouseover|focus|blur|change|input|keydown|keyup)\s*="
            r"|<img[^>]+src\s*=\s*['\"]?\s*x"
            r"|<iframe\b"
            r"|eval\s*\("
            r"|document\s*\.\s*(cookie|write|location)"
            r"|window\s*\.\s*(location|open)"
            r"|\balert\s*\("
            r"|\bprompt\s*\("
            r"|\bconfirm\s*\()",
            re.IGNORECASE,
        ),

        "Path_Traversal": re.compile(
            r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e)"
            r"|(etc/passwd|etc/shadow|win/system32"
            r"|proc/self/environ"
            r"|boot\.ini)",
            re.IGNORECASE,
        ),

        "XXE": re.compile(
            r"(<!entity\b"
            r"|<!doctype\b"
            r"|system\s+['\"]https?://"
            r"|file:///)",
            re.IGNORECASE,
        ),

        "RCE": re.compile(
            r"(;\s*(ls|cat|wget|curl|bash|sh|python|perl|ruby|nc|whoami|uname|id)\b"
            r"|\|\s*(ls|cat|wget|curl|bash|sh|python)\b"
            r"|`[^`]{1,50}`"
            r"|\$\([^)]{1,50}\)"
            r"|\bpassthru\s*\("
            r"|\bexec\s*\("
            r"|\bsystem\s*\("
            r"|/bin/(sh|bash)"
            r"|\bpowershell\b)",
            re.IGNORECASE,
        ),

        "Auth_Abuse": re.compile(
            r"(password=.{0,30}&password="
            r"|\badmin\b.{0,20}\bpassword\b"
            r"|Authorization:\s*Basic\s+[A-Za-z0-9+/]{4,})",
            re.IGNORECASE,
        ),
    }

    def __init__(self):
        self._norm = PayloadNormalizer()

    def check(self, url: str, content: str, user_agent: str) -> tuple[list, str, str]:
        """
        คืน (matched_tags, normalized_url, normalized_content)
        """
        norm_url     = self._norm.normalize(url)
        norm_content = self._norm.normalize(content)
        combined     = f"{norm_url} {norm_content} {user_agent.lower()}"

        matched = [tag for tag, pat in self.PATTERNS.items() if pat.search(combined)]
        return matched, norm_url, norm_content


# ══════════════════════════════════════════════════════════════
#  LAYER 2: ENTROPY / OBFUSCATION   (จาก v1 — v2 ไม่มี)
# ══════════════════════════════════════════════════════════════

_ENTROPY_THRESHOLD   = 5.0
_ENTROPY_MIN_LEN     = 20
_SPECIAL_CHAR_RATIO  = 0.15
_SPECIAL_CHARS       = set("!@#$%^&*(){}[]|\\:;\"'<>,.?/~`+=")


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = defaultdict(int)
    for c in text:
        freq[c] += 1
    n = len(text)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _layer2_entropy(raw_url: str, raw_content: str) -> tuple[Optional[str], float]:
    """
    คืน (reason | None, entropy_score)
    """
    combined = (raw_url + " " + raw_content).strip()
    if len(combined) < _ENTROPY_MIN_LEN:
        return None, 0.0

    score = _shannon_entropy(combined)
    if score > _ENTROPY_THRESHOLD:
        return f"High entropy ({score:.2f}) — possible obfuscation", score

    ratio = sum(1 for c in combined if c in _SPECIAL_CHARS) / len(combined)
    if ratio > _SPECIAL_CHAR_RATIO:
        return f"High special-char ratio ({ratio:.1%})", score

    params = re.findall(r"[?&]([^&]{80,})", raw_url)
    if params:
        return f"Abnormally long URL param ({len(params[0])} chars)", score

    return None, score


# ══════════════════════════════════════════════════════════════
#  LAYER 3: STATEFUL BEHAVIOR   (จาก v1 — v2 ไม่มี)
# ══════════════════════════════════════════════════════════════

_RATE_WINDOW    = 60    # วินาที
_RATE_MAX       = 100   # req สูงสุดต่อ IP ต่อ window
_ERROR_MAX      = 20    # 4xx/5xx สูงสุดต่อ IP ต่อ window
_PATH_DIV_MAX   = 30    # unique path สูงสุดต่อ IP ต่อ window

_ip_req   : dict = defaultdict(deque)
_ip_err   : dict = defaultdict(deque)
_ip_paths : dict = defaultdict(set)
_ip_ptime : dict = {}


def _layer3_behavior(ip: str, url: str, status_code: int) -> Optional[str]:
    if not ip:
        return None
    now = time.time()

    def clean(dq):
        while dq and (now - dq[0]) > _RATE_WINDOW:
            dq.popleft()

    req_dq = _ip_req[ip]
    clean(req_dq)
    req_dq.append(now)
    if len(req_dq) > _RATE_MAX:
        return f"Rate limit exceeded: {len(req_dq)} req/{_RATE_WINDOW}s (IP: {ip})"

    if status_code >= 400:
        err_dq = _ip_err[ip]
        clean(err_dq)
        err_dq.append(now)
        if len(err_dq) > _ERROR_MAX:
            return f"Excessive errors: {len(err_dq)} errors/{_RATE_WINDOW}s (IP: {ip})"

    if now - _ip_ptime.get(ip, 0) > _RATE_WINDOW:
        _ip_paths[ip] = set()
        _ip_ptime[ip] = now
    _ip_paths[ip].add(url.split("?")[0])
    if len(_ip_paths[ip]) > _PATH_DIV_MAX:
        return f"Path scanning: {len(_ip_paths[ip])} unique paths/{_RATE_WINDOW}s (IP: {ip})"

    return None


# ══════════════════════════════════════════════════════════════
#  LAYER 4: RANDOM SAMPLING   (จาก v1 — v2 ไม่มี)
# ══════════════════════════════════════════════════════════════

_SAMPLE_RATE = 0.05  # 5% ของ Log ที่ผ่านทุก Layer


def _layer4_sampling() -> bool:
    return random.random() < _SAMPLE_RATE


# ══════════════════════════════════════════════════════════════
#  PRE-FILTER PIPELINE  — รวมทั้ง 4 Layer
# ══════════════════════════════════════════════════════════════

_heuristic = HeuristicEngine()


def run_pipeline(log_data: dict) -> FilterResult:
    """
    รัน 4 Layer แล้วคืน FilterResult
    .risk_level == SAFE       → ข้ามได้
    .risk_level == SUSPICIOUS → ส่ง LLM
    """
    url         = log_data.get("URL", "")
    content     = log_data.get("content", "")
    user_agent  = log_data.get("User-Agent", "")
    status_code = int(log_data.get("Status-Code", 200) or 200)
    ip          = log_data.get("ip", "")

    # ── Layer 1: Regex ───────────────────────────────────────
    matched_tags, norm_url, norm_content = _heuristic.check(url, content, user_agent)
    if matched_tags:
        return FilterResult(
            risk_level=RiskLevel.SUSPICIOUS,
            matched_tags=matched_tags,
            layer=1,
            reason=f"Regex matched: {', '.join(matched_tags)}",
            normalized_url=norm_url,
            normalized_content=norm_content,
        )

    # ── Layer 2: Entropy ─────────────────────────────────────
    entropy_reason, score = _layer2_entropy(url, content)
    if entropy_reason:
        return FilterResult(
            risk_level=RiskLevel.SUSPICIOUS,
            matched_tags=[],
            layer=2,
            reason=entropy_reason,
            normalized_url=norm_url,
            normalized_content=norm_content,
            entropy_score=score,
        )

    # ── Layer 3: Behavior ────────────────────────────────────
    behavior_reason = _layer3_behavior(ip, url, status_code)
    if behavior_reason:
        return FilterResult(
            risk_level=RiskLevel.SUSPICIOUS,
            matched_tags=[],
            layer=3,
            reason=behavior_reason,
            normalized_url=norm_url,
            normalized_content=norm_content,
        )

    # ── Layer 4: Sample ──────────────────────────────────────
    if _layer4_sampling():
        return FilterResult(
            risk_level=RiskLevel.SUSPICIOUS,
            matched_tags=[],
            layer=4,
            reason="Random audit sample (5%)",
            normalized_url=norm_url,
            normalized_content=norm_content,
        )

    # ── Safe ─────────────────────────────────────────────────
    return FilterResult(
        risk_level=RiskLevel.SAFE,
        matched_tags=[],
        layer=0,
        reason="Passed all layers",
        normalized_url=norm_url,
        normalized_content=norm_content,
    )


# ══════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════

def _ensure_csv_header():
    if not os.path.exists(LOG_CSV_PATH):
        with open(LOG_CSV_PATH, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                "timestamp", "method", "url", "user_agent",
                "heuristic_tags", "filter_layer", "filter_reason",
                "status", "attack_type", "ai_analysis",
            ])


def _sanitize_prompt_tokens(text: str) -> str:
    """ป้องกัน Prompt Injection ผ่าน Special Tokens ของ LLaMA  (จาก v2)"""
    for token in ["<|eot_id|>", "<|start_header_id|>", "<|end_header_id|>", "<|begin_of_text|>"]:
        text = text.replace(token, "[FILTERED]")
    return text


# ══════════════════════════════════════════════════════════════
#  SOC AGENT
# ══════════════════════════════════════════════════════════════

class SOCAgent:
    def __init__(self):
        self.alerts    = []
        self.all_logs  = []

        self.vector_store = None
        self.model        = None
        self.tokenizer    = None

        # Stats
        self._stats = {
            "total": 0, "skipped_safe": 0,
            "sent_to_llm": 0, "confirmed_attack": 0, "false_positive": 0,
            "layer_counts": {1: 0, 2: 0, 3: 0, 4: 0},
        }

        self.request_queue = queue.Queue(maxsize=500)
        self.data_lock     = threading.Lock()

        _ensure_csv_header()
        self.setup_rag()
        self.setup_llm()

        self._worker = threading.Thread(target=self._inference_worker, daemon=True)
        self._worker.start()
        print("🔄 Queue Worker + Pre-Filter Pipeline (4 Layer) พร้อมใช้งาน!")

    # ── Setup ──────────────────────────────────────────────────

    def setup_rag(self):
        print("📚 กำลังเชื่อมต่อระบบ RAG...")
        try:
            self.vector_store = SOCVectorStore()
            if self.vector_store.load_index(index_path=FAISS_INDEX, data_path=FAISS_DATA):
                print("✅ RAG พร้อมใช้งาน")
            else:
                print("⚠️  ไม่พบ FAISS Index (ทำงานได้โดยไม่มีความรู้เก่า)")
        except Exception as e:
            print(f"⚠️  RAG Setup Error: {e}")

    def setup_llm(self):
        print("🤖 กำลังโหลดโมเดล SOC Analyst...")
        if not os.path.exists(MODEL_ID):
            print(f"⚠️  ไม่พบโฟลเดอร์โมเดล: {MODEL_ID}")
            return
        try:
            self.model, self.tokenizer = FastLanguageModel.from_pretrained(
                model_name=MODEL_ID, max_seq_length=1024, dtype=None, load_in_4bit=True,
            )
            FastLanguageModel.for_inference(self.model)
            print("✅ AI SOC Analyst พร้อมทำงาน! (Unsloth Fast Inference 🚀)")
        except Exception as e:
            print(f"⚠️  Model Load Error: {e}")

    # ── Queue Worker ───────────────────────────────────────────

    def _inference_worker(self):
        print("✅ Inference Worker รอรับงานจาก Queue")
        while True:
            try:
                item = self.request_queue.get(block=True, timeout=1)
                self._run_pipeline(item)
                self.request_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"⚠️  Worker Error: {e}")

    # ── 2-Stage Pipeline ───────────────────────────────────────

    def _run_pipeline(self, log_data: dict):
        """
        Stage 1 → Pre-Filter (4 Layer)
        Stage 2 → LLM Reasoning (เฉพาะที่ SUSPICIOUS)
        """
        with self.data_lock:
            self._stats["total"] += 1

        f: FilterResult = run_pipeline(log_data)

        if f.risk_level == RiskLevel.SAFE:
            with self.data_lock:
                self._stats["skipped_safe"] += 1
            self._save_result(
                log_data, f, is_attack=False,
                attack_type="Normal", ai_analysis="[Passed pre-filter — Safe]",
            )
            return

        # SUSPICIOUS → LLM
        with self.data_lock:
            self._stats["sent_to_llm"] += 1
            self._stats["layer_counts"][f.layer] = self._stats["layer_counts"].get(f.layer, 0) + 1

        tags_str = ", ".join(f.matched_tags) if f.matched_tags else f"Layer {f.layer}"
        print(f"🔍 [{tags_str}] → ส่งให้ LLM ยืนยัน | {f.reason}")

        if not self.model:
            # ไม่มีโมเดล → เชื่อ Heuristic
            self._save_result(
                log_data, f, is_attack=bool(f.matched_tags),
                attack_type=f.matched_tags[0] if f.matched_tags else "Suspicious",
                ai_analysis="[No LLM — Heuristic/Entropy/Behavior only]",
            )
            return

        self._run_llm_reasoning(log_data, f)

    def _run_llm_reasoning(self, log_data: dict, f: FilterResult):
        """Stage 2: LLM ตัดสิน False Positive หรือ Confirmed Attack"""

        tags_str = ", ".join(f.matched_tags) if f.matched_tags else f"Layer {f.layer} anomaly"

        # Sanitize inputs ก่อนใส่ Prompt  (จาก v2)
        safe_url     = _sanitize_prompt_tokens(f.normalized_url[:200])
        safe_content = _sanitize_prompt_tokens(f.normalized_content[:200])
        safe_ua      = _sanitize_prompt_tokens(log_data.get("User-Agent", "")[:100])

        log_text = (
            f"Method: {log_data.get('Method','')[:10]} | "
            f"URL: {safe_url} | "
            f"Status: {log_data.get('Status-Code','Unknown')} | "
            f"Content: {safe_content} | "
            f"UA: {safe_ua}"
        )

        # RAG Context
        context = ""
        if self.vector_store and self.vector_store.index:
            try:
                similar = self.vector_store.search_similar(log_text, k=2)
                if similar:
                    context = "### PAST CASES:\n" + "".join(
                        f"- {i['log']} → {'Attack' if str(i['label'])=='1' else 'Normal'}\n"
                        for i in similar
                    )
            except Exception:
                pass

        # Prompt — บอก LLM ว่า Layer ไหนตั้งธงและทำไม
        system_prompt = f"""You are an expert SOC Analyst.
A pre-filter flagged this log: [{tags_str}]
Reason: {f.reason}
Layer: {f.layer} (1=Regex, 2=Entropy/Obfuscation, 3=Behavior anomaly, 4=Audit sample)

Your job: CONFIRM or DISMISS the flag.

RULES:
1. If benign (e.g. search query naturally containing "or", high-entropy but normal JWT),
   respond "Normal traffic — False Positive" with brief explanation.
2. If real attack, respond with:
   - Classification: <type>
   - Severity: Critical / High / Medium / Low
   - Explanation: <1-2 sentences>
   - Remediation: <short action>
3. Be concise. No hallucinations."""

        prompt = (
            f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n"
            f"{system_prompt}\n{context}"
            f"<|eot_id|><|start_header_id|>user<|end_header_id|>\n"
            f"Analyze: {log_text}"
            f"<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n"
        )

        # Inference
        try:
            inputs = self.tokenizer(prompt, return_tensors="pt").to("cuda")
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=250,
                    do_sample=False,
                    pad_token_id=self.tokenizer.eos_token_id,
                    repetition_penalty=1.1,
                )
            response = self.tokenizer.decode(
                outputs[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True
            )
        except Exception as e:
            print(f"⚠️  Inference Error: {e}")
            return

        # ── ตัดสิน False Positive  (จาก v2 — ดีกว่า v1)
        resp_upper = response.upper()
        is_fp = ("FALSE POSITIVE" in resp_upper or
                 "NORMAL TRAFFIC" in resp_upper or
                 "BENIGN" in resp_upper or
                 "LEGITIMATE" in resp_upper)

        if is_fp:
            print(f"✅ [LLM: False Positive] {tags_str} dismissed")
            with self.data_lock:
                self._stats["false_positive"] += 1
            self._save_result(
                log_data, f, is_attack=False,
                attack_type="Normal (FP dismissed)",
                ai_analysis=response.strip()[:500],
            )
            return

        # ── ยืนยัน Attack
        is_attack = (
            ("ATTACK" in resp_upper or "MALICIOUS" in resp_upper or
             "CRITICAL" in resp_upper or "CLASSIFICATION" in resp_upper) and
            "NO ATTACK" not in resp_upper
        ) or "LABEL: 1" in resp_upper

        # refine attack_type จาก LLM response
        attack_type = f.matched_tags[0].replace("_", " ") if f.matched_tags else "Suspicious"
        for kw, label in [
            ("SQL INJECTION","SQLi"), ("SQLI","SQLi"),
            ("XSS","XSS"),            ("CROSS-SITE","XSS"),
            ("PATH TRAVERSAL","Path Traversal"), ("LFI","Path Traversal"),
            ("XXE","XXE"),
            ("RCE","RCE"),            ("COMMAND INJECTION","RCE"),
        ]:
            if kw in resp_upper:
                attack_type = label
                break

        if is_attack:
            with self.data_lock:
                self._stats["confirmed_attack"] += 1
            print("=" * 60)
            print(f"🚨 [SOC ALERT] [{attack_type}] — Layer {f.layer}: {f.reason}")
            print(f"🎯 เป้าหมาย: {log_data.get('URL')}")
            print(f"📝 LLM:\n{response.strip()}")
            print("=" * 60)

        self._save_result(log_data, f, is_attack=is_attack,
                          attack_type=attack_type, ai_analysis=response.strip()[:500])

    # ── Save ───────────────────────────────────────────────────

    def _save_result(
        self, log_data: dict, f: FilterResult,
        is_attack: bool, attack_type: str, ai_analysis: str,
    ):
        timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status_str = "ALERT" if is_attack else "Normal"
        tags_str   = "|".join(f.matched_tags) if f.matched_tags else "-"

        with open(LOG_CSV_PATH, "a", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerow([
                timestamp,
                log_data.get("Method", ""),
                log_data.get("URL", "")[:300],
                log_data.get("User-Agent", "")[:100],
                tags_str,
                f.layer,        # ← Layer ที่ตรวจพบ
                f.reason[:200], # ← เหตุผล
                status_str,
                attack_type,
                ai_analysis[:500],
            ])

        entry = {
            "timestamp":      timestamp,
            "method":         log_data.get("Method", ""),
            "url":            log_data.get("URL", "")[:200],
            "heuristic_tags": f.matched_tags,
            "filter_layer":   f.layer,
            "filter_reason":  f.reason,
            "status":         status_str,
            "attack_type":    attack_type,
            "ai_analysis":    ai_analysis[:500],
        }

        with self.data_lock:
            self.all_logs.append(entry)
            if len(self.all_logs) > 200:
                self.all_logs = self.all_logs[-200:]
            if is_attack:
                self.alerts.append({
                    "timestamp": timestamp, "status": "ALERT",
                    "target":       log_data.get("URL", "Unknown"),
                    "method":       log_data.get("Method", "Unknown"),
                    "heuristic_tags": f.matched_tags,
                    "filter_layer": f.layer,
                    "attack_type":  attack_type,
                    "analysis":     ai_analysis,
                })

    # ── Public API ─────────────────────────────────────────────

    def analyze_request(self, log_data: dict):
        """Non-blocking — ใส่งานเข้า Queue"""
        try:
            self.request_queue.put_nowait(log_data)
        except queue.Full:
            print("⚠️  Queue เต็ม (500)! ทิ้ง request นี้")

    def get_recent_alerts(self):
        with self.data_lock:
            return list(self.alerts[-10:])

    def get_dashboard_stats(self):
        with self.data_lock:
            total   = len(self.all_logs)
            attacks = [l for l in self.all_logs if l["status"] == "ALERT"]
            attack_types = {"Normal": total - len(attacks)}
            for a in attacks:
                t = a.get("attack_type", "Unknown")
                attack_types[t] = attack_types.get(t, 0) + 1
            stats_snap = dict(self._stats)

        total_recv = stats_snap["total"]
        return {
            "total_requests": total,
            "total_attacks":  len(attacks),
            "total_normal":   total - len(attacks),
            "attack_types":   attack_types,
            "recent_logs":    self.all_logs[-50:],
            "pipeline_stats": {
                "total_processed":    total_recv,
                "skipped_by_filter":  stats_snap["skipped_safe"],
                "sent_to_llm":        stats_snap["sent_to_llm"],
                "confirmed_attack":   stats_snap["confirmed_attack"],
                "false_positive":     stats_snap["false_positive"],
                "llm_reduction":      (
                    f"{(1 - stats_snap['sent_to_llm'] / max(total_recv, 1)) * 100:.1f}%"
                ),
                "layer_breakdown":    stats_snap["layer_counts"],
            },
        }