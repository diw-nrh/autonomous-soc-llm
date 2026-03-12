from engine import ModelLoader, analyze_single

def main():
    # 1. โหลดโมเดล
    model_id = "meta-llama/Llama-3.2-3B-Instruct"
    loader = ModelLoader(model_id)
    model, tokenizer = loader.load_for_soc()

    # 2. ทดสอบวิเคราะห์ Log
    test_log = "GET /login.php?user=admin' OR '1'='1' HTTP/1.1"
    print(f"\n🔍 กำลังวิเคราะห์ Log: {test_log}")
    
    result = analyze_single(model, tokenizer, test_log)
    
    print("\n" + "="*50)
    print(f"🛡️ ผลการวิเคราะห์: {result}")
    print("="*50)

if __name__ == "__main__":
    main()