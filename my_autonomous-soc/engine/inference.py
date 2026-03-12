# engine/inference.py
import torch

def analyze_log(model, tokenizer, log_text, similar_logs=None):
    context = ""
    if similar_logs:
        context = "### REFERENCE FROM DATABASE:\n"
        for i, item in enumerate(similar_logs):
            lbl = "Normal (0)" if str(item['label']) == '0' else "Attack (1)"
            context += f"- Past Case: {item['log']} | Result: {lbl}\n"

    prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>
You are a SOC Expert. Distinguish between a 'Normal' request and a 'Real Attack'.
CRITICAL: Do not flag as '1' just because you see symbols. Flag as '1' ONLY if you see a logical attack payload (e.g., SQL keywords, Script tags, Directory traversal).

{context}

### TASK:
1. Reason: Is there a logical exploit pattern? (Yes/No)
2. Final Conclusion: Answer ONLY '0' or '1' at the end after 'RESULT:'.

NEW LOG: {log_text}
Analysis: <|eot_id|><|start_header_id|>assistant<|end_header_id|>"""

    inputs = tokenizer(prompt, return_tensors="pt").to("cuda")
    with torch.no_grad():
        outputs = model.generate(
            **inputs, 
            max_new_tokens=80, 
            temperature=0.01,
            pad_token_id=tokenizer.eos_token_id
        )
    
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    # ค้นหาคำตอบจากส่วนท้ายสุดของข้อความที่ AI เขียน
    if "RESULT: 1" in response.upper() or "RESULT:1" in response.upper():
        return "1"
    return "0"