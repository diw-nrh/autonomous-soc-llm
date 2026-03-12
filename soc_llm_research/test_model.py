from unsloth import FastLanguageModel
import torch

# 1. โหลดโมเดลที่คุณเพิ่งเทรนเสร็จ
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name = "soc_lora_model",
    max_seq_length = 2048,
    load_in_4bit = True,
)
FastLanguageModel.for_inference(model) # ทำให้โมเดลรันเร็วขึ้น 2 เท่า

# 2. ใส่ Log ที่คุณต้องการทดสอบ (ตัวอย่าง)
log_input = "Feb 15 10:05:22 server1 sshd[1234]: Failed password for root from 192.168.1.105 port 54321 ssh2"

inputs = tokenizer(
    [
        f"Analyze this log and identify if it is an attack:\n{log_input}\n\nResponse:"
    ], return_tensors = "pt").to("cuda")

# 3. ให้โมเดลตอบ
outputs = model.generate(**inputs, max_new_tokens = 64)
print(tokenizer.batch_decode(outputs)[0])