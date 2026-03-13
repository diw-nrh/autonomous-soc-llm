# prepare_dataset.py
import pandas as pd
import json
import os
import random

def prepare_data():
    csv_path = "data/csic_database.csv"
    if not os.path.exists(csv_path):
        print("❌ ไม่พบไฟล์ CSV!")
        return

    df = pd.read_csv(csv_path)
    dataset = []

    print("🧹 กำลังแปลงข้อมูลเป็นรูปแบบ Fine-Tuning...")
    for _, row in df.iterrows():
        # รวมข้อมูลสำคัญเพื่อสร้าง Input
        # แก้ไขชื่อคอลัมน์ให้ตรงตาม Dataset ของคุณ (User-Agen, lenght)
        input_text = (
            f"Method: {row['Method']} | "
            f"URL: {row['URL']} | "
            f"Content: {row.get('content', '')} | "
            f"UA: {row.get('User-Agen', '')}"
        )
        
        # รูปแบบ Alpaca format ที่ Unsloth ชอบใช้
        entry = {
            "instruction": "Analyze the HTTP request and classify as '0' (Normal) or '1' (Malicious).",
            "input": input_text,
            "output": str(row['classification'])
        }
        dataset.append(entry)

    random.seed(42)
    random.shuffle(dataset)
    split_idx = int(len(dataset) * 0.9)
    train_data = dataset[:split_idx]
    test_data = dataset[split_idx:]

    # บันทึกไฟล์ Train (90%)
    with open("data/train_data.jsonl", "w", encoding="utf-8") as f:
        for entry in train_data:
            f.write(json.dumps(entry) + "\n")
            
    # บันทึกไฟล์ Test (10%) สำหรับใช้วัดผล Evaluate
    with open("data/test_data.jsonl", "w", encoding="utf-8") as f:
        for entry in test_data:
            f.write(json.dumps(entry) + "\n")
            
    print(f"✅ เตรียมข้อมูลสำเร็จ! Train: {len(train_data)} | Test: {len(test_data)} รายการ")
    print("ไฟล์ถูกบันทึกที่: data/train_data.jsonl และ data/test_data.jsonl")

if __name__ == "__main__":
    prepare_data()