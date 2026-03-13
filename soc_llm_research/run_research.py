# run_research.py
import pandas as pd
from engine import ModelLoader, analyze_log, clean_log, SOCVectorStore
from sklearn.metrics import classification_report, confusion_matrix
from tqdm import tqdm

def main():
    # 1. โหลดโมเดล (VRAM 2.1 GB)
    loader = ModelLoader()
    model, tokenizer = loader.load_for_soc()

    # 2. จัดการ RAG Vector Store (เช็คไฟล์ Save ก่อน)
    vector_store = SOCVectorStore()
    
    # --- ใส่ตรงนี้ครับ ---
    if vector_store.load_index():
        # ถ้ามีไฟล์ save อยู่แล้ว (soc_index.faiss และ soc_data.csv) จะโหลดขึ้นมาทันที
        print("⚡ ใช้ฐานความรู้เดิมจากไฟล์ Save...")
    else:
        # ถ้ายังไม่มีไฟล์ save ให้สร้างใหม่จาก 6 หมื่นบรรทัด (รันนานหน่อยแค่ครั้งแรก)
        vector_store.build_index("data/csic_database.csv")
        # สร้างเสร็จแล้วสั่ง Save เก็บไว้เลย
        vector_store.save_index()
    # ------------------

    # 3. เตรียม Test Set แบบ Balanced (0 และ 1 อย่างละ 25 รายการ)
    df = pd.read_csv("data/csic_database.csv")
    normal_samples = df[df['classification'] == 0].sample(25, random_state=42)
    attack_samples = df[df['classification'] == 1].sample(25, random_state=42)
    test_set = pd.concat([normal_samples, attack_samples]).sample(frac=1)

    print(f"🔍 วิเคราะห์ {len(test_set)} รายการ ด้วยเทคนิค RAG...")
    
    y_true, y_pred = [], []

    for _, row in tqdm(test_set.iterrows(), total=len(test_set)):
        actual_label = str(row['classification'])
        log_content = clean_log(row)
        
        # ดึงตัวอย่างที่ใกล้เคียงที่สุดจากฐานข้อมูล 3 รายการ
        similar_cases = vector_store.search_similar(log_content, k=3)
        
        # วิเคราะห์โดยใช้ความรู้จาก RAG
        prediction = analyze_log(model, tokenizer, log_content, similar_logs=similar_cases)
        
        y_true.append(actual_label)
        y_pred.append(prediction)

    # 4. แสดงผลลัพธ์
    print("\n" + "="*50)
    print("📊 รายงานวิจัย Autonomous SOC (Llama 3.2 + RAG)")
    print("="*50)
    print(classification_report(y_true, y_pred, target_names=['Normal (0)', 'Attack (1)']))
    print("\n[Confusion Matrix]")
    print(confusion_matrix(y_true, y_pred))

if __name__ == "__main__":
    main()