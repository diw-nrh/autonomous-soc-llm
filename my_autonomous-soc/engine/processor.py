# engine/processor.py
import urllib.parse

def clean_log(row):
    # ปรับชื่อคอลัมน์ให้ตรงตามภาพ image_8d45b8.png
    important_cols = [
        'Method', 'URL', 'content', 'User-Agen', 
        'cookie', 'content-type', 'lenght'
    ]
    
    log_parts = []
    for col in important_cols:
        val = str(row.get(col, ""))
        if val and val.lower() != "nan" and val != "":
            log_parts.append(f"{col}: {val}")
            
    return " | ".join(log_parts)
    
    log_parts = []
    for col in important_cols:
        val = str(row.get(col, ""))
        if val and val.lower() != "nan" and val != "":
            # Decode URL (%20 -> space, %27 -> ') เพื่อให้ AI เห็นคำสั่งโจมตีชัดๆ
            decoded_val = urllib.parse.unquote(val)
            log_parts.append(f"{col}: {decoded_val}")
            
    return " | ".join(log_parts)