import faiss
import numpy as np
import pandas as pd
import os
from sentence_transformers import SentenceTransformer

class SOCVectorStore:
    def __init__(self, model_name='all-MiniLM-L6-v2'):
        # โหลดโมเดลสำหรับแปลง Log เป็นตัวเลข (Embedding)
        self.embedder = SentenceTransformer(model_name)
        self.index = None
        self.data = None

    def build_index(self, csv_path):
        """สร้างฐานความรู้ใหม่จากไฟล์ CSV ทั้งหมด"""
        print(f"📚 กำลังอ่านไฟล์ {csv_path} และสร้างฐานความรู้ (อาจใช้เวลาสักครู่)...")
        df = pd.read_csv(csv_path)
        
        # รวมข้อมูลเพื่อใช้ทำ Embedding
        df['text_for_embed'] = df['Method'].astype(str) + " " + \
                               df['URL'].fillna('').astype(str) + " " + \
                               df['content'].fillna('').astype(str)
        
        # แปลงข้อความเป็นเวกเตอร์
        embeddings = self.embedder.encode(df['text_for_embed'].tolist(), show_progress_bar=True)
        
        # สร้าง Index ของ FAISS
        self.index = faiss.IndexFlatL2(embeddings.shape[1])
        self.index.add(np.array(embeddings).astype('float32'))
        self.data = df
        print("✅ สร้างฐานความรู้ใน RAM สำเร็จ!")

    def search_similar(self, query_text, k=3):
        """ค้นหา Log ที่หน้าตาคล้ายกันที่สุด k รายการ"""
        if self.index is None:
            raise ValueError("ยังไม่ได้โหลด Index! กรุณารัน build_index หรือ load_index ก่อน")
            
        query_vec = self.embedder.encode([query_text])
        distances, indices = self.index.search(np.array(query_vec).astype('float32'), k)
        
        results = []
        for i in indices[0]:
            results.append({
                'log': f"{self.data.iloc[i]['Method']} {self.data.iloc[i]['URL']} {self.data.iloc[i]['content']}",
                'label': self.data.iloc[i]['classification']
            })
        return results

    # --- วางฟังก์ชันใหม่ตรงนี้ครับ ---
    
    def save_index(self):
        # หาตำแหน่ง Folder ปัจจุบันของไฟล์นี้
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        output_dir = os.path.join(base_dir, "outputs")
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        index_path = os.path.join(output_dir, "soc_index.faiss")
        data_path = os.path.join(output_dir, "soc_data.csv")
        
        faiss.write_index(self.index, index_path)
        self.data.to_csv(data_path, index=False)
        print(f"💾 Pattern บันทึกสำเร็จที่: {index_path}")

    def load_index(self, index_path="outputs/soc_index.faiss", data_path="outputs/soc_data.csv"):
        """โหลด Pattern ที่เคยบันทึกไว้ขึ้นมาใช้งานทันที"""
        if os.path.exists(index_path) and os.path.exists(data_path):
            self.index = faiss.read_index(index_path)
            self.data = pd.read_csv(data_path)
            print("⚡ โหลดฐานความรู้เดิมสำเร็จ! (ไม่ต้องสร้างใหม่)")
            return True
        return False