"""Merge the LoRA adapter into the base model and save a plain Hugging Face model dir (fp16), ready for GGUF conversion.

    python training/merge_export.py --adapter training/out/adapter --out training/out/merged

Merging is done on the CPU in fp16/fp32 (needs ~7 GB RAM for the 3B model), so it works on the free Colab runtime and on a laptop.
The base is read from the adapter's own config, so it cannot be mixed up.
"""
import argparse
import json
import os


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--adapter", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--base", help="override the base recorded in the adapter")
    p.add_argument("--fp32", action="store_true", help="merge in float32 (use for CPU smoke tests)")
    a = p.parse_args()
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    base = a.base or json.load(open(os.path.join(a.adapter, "adapter_config.json")))["base_model_name_or_path"]
    dtype = torch.float32 if a.fp32 else torch.float16
    try:
        model = AutoModelForCausalLM.from_pretrained(base, dtype=dtype, low_cpu_mem_usage=True)
    except TypeError:
        model = AutoModelForCausalLM.from_pretrained(base, torch_dtype=dtype, low_cpu_mem_usage=True)
    model = PeftModel.from_pretrained(model, a.adapter).merge_and_unload()
    os.makedirs(a.out, exist_ok=True)
    model.save_pretrained(a.out, safe_serialization=True)
    AutoTokenizer.from_pretrained(base).save_pretrained(a.out)
    print("merged model saved to", a.out, "(base:", base + ")")


if __name__ == "__main__":
    main()
