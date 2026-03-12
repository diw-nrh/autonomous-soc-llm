import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
# โหลดโมเดลแบบประหยัด VRAM)
class ModelLoader:
    def __init__(self, model_id="meta-llama/Llama-3.2-3B-Instruct"):
        self.model_id = model_id

    def load_for_soc(self):
        print(f"🚀 กำลังเพิ่มขีดความสามารถ GPU สำหรับ {self.model_id}...")
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True
        )
        tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        tokenizer.pad_token = tokenizer.eos_token
        
        model = AutoModelForCausalLM.from_pretrained(
            self.model_id,
            quantization_config=bnb_config,
            device_map="auto"
        )
        return model, tokenizer