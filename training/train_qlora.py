"""QLoRA fine-tune of the SPIDER reviewer model on training/data/train.jsonl (made by prep_data.py).

    python training/train_qlora.py --out training/out/adapter                      # GPU, 4-bit QLoRA (Colab T4)
    python training/train_qlora.py --base sshleifer/tiny-gpt2 --no-4bit --max-steps 3 --out /tmp/a   # CPU smoke test

Prompt format: the plain Llama 3 chat format, written out by hand (see render()). It is the same text the
Ollama Modelfile in training/Modelfile produces, so what the model sees in training is what it sees in the tool.
Loss is computed on the assistant answer only. Examples longer than --max-seq tokens are skipped, never truncated.
"""
import argparse
import json
import math
import os
import random

DEFAULT_BASE = "chuanli11/Llama-3.2-3B-Instruct-uncensored"


def render(messages):
    """Return (prompt_text, answer_text) in Llama 3 chat format (BOS is added by the tokenizer)."""
    prompt = ""
    for m in messages[:-1]:
        prompt += f"<|start_header_id|>{m['role']}<|end_header_id|>\n\n{m['content']}<|eot_id|>"
    prompt += "<|start_header_id|>assistant<|end_header_id|>\n\n"
    return prompt, messages[-1]["content"] + "<|eot_id|>"


def encode(tok, messages, max_seq):
    prompt, answer = render(messages)
    p = tok(prompt, add_special_tokens=True)["input_ids"]
    if tok.bos_token_id is not None and p[:2] == [tok.bos_token_id, tok.bos_token_id]:
        p = p[1:]
    a = tok(answer, add_special_tokens=False)["input_ids"]
    if len(p) + len(a) > max_seq:
        return None
    return {"input_ids": p + a, "labels": [-100] * len(p) + a}


def load_rows(path, tok, max_seq, limit=None):
    rows, skipped = [], 0
    for line in open(path, encoding="utf-8"):
        if not line.strip():
            continue
        e = encode(tok, json.loads(line)["messages"], max_seq)
        if e is None:
            skipped += 1
        else:
            rows.append(e)
    if limit:
        rows = rows[:limit]
    return rows, skipped


class Collator:
    def __init__(self, pad_id):
        self.pad = pad_id

    def __call__(self, batch):
        import torch
        n = max(len(b["input_ids"]) for b in batch)
        ids = torch.full((len(batch), n), self.pad, dtype=torch.long)
        lab = torch.full((len(batch), n), -100, dtype=torch.long)
        att = torch.zeros((len(batch), n), dtype=torch.long)
        for i, b in enumerate(batch):
            k = len(b["input_ids"])
            ids[i, :k] = torch.tensor(b["input_ids"])
            lab[i, :k] = torch.tensor(b["labels"])
            att[i, :k] = 1
        return {"input_ids": ids, "labels": lab, "attention_mask": att}


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base", default=DEFAULT_BASE)
    p.add_argument("--train", default=os.path.join(here, "data", "train.jsonl"))
    p.add_argument("--val", default=os.path.join(here, "data", "val.jsonl"))
    p.add_argument("--out", default=os.path.join(here, "out", "adapter"))
    p.add_argument("--epochs", type=float, default=3)
    p.add_argument("--lr", type=float, default=2e-4)
    p.add_argument("--max-seq", type=int, default=2048)
    p.add_argument("--batch", type=int, default=1)
    p.add_argument("--grad-accum", type=int, default=16)
    p.add_argument("--lora-r", type=int, default=16)
    p.add_argument("--lora-alpha", type=int, default=32)
    p.add_argument("--lora-dropout", type=float, default=0.05)
    p.add_argument("--max-steps", type=int, default=-1, help="stop early (smoke tests)")
    p.add_argument("--limit", type=int, help="use only the first N training rows (smoke tests)")
    p.add_argument("--no-4bit", action="store_true", help="no bitsandbytes: plain LoRA (CPU smoke tests, or big GPUs)")
    p.add_argument("--seed", type=int, default=7)
    a = p.parse_args()

    import torch
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    from transformers import AutoModelForCausalLM, AutoTokenizer, Trainer, TrainingArguments

    random.seed(a.seed)
    torch.manual_seed(a.seed)
    cuda = torch.cuda.is_available()
    if not cuda and not a.no_4bit:
        raise SystemExit("No GPU found. In Colab: Runtime > Change runtime type > T4 GPU. "
                         "For a CPU-only smoke test add --no-4bit and a tiny --base.")
    bf16 = cuda and torch.cuda.is_bf16_supported()  # T4 has no bf16 -> fp16
    dtype = torch.bfloat16 if bf16 else (torch.float16 if cuda else torch.float32)

    tok = AutoTokenizer.from_pretrained(a.base)
    if tok.pad_token_id is None:
        tok.pad_token = tok.eos_token
    kw = {}
    if not a.no_4bit:
        from transformers import BitsAndBytesConfig
        kw["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=dtype)
        kw["device_map"] = {"": 0}
    try:
        model = AutoModelForCausalLM.from_pretrained(a.base, dtype=dtype, **kw)
    except TypeError:  # older transformers
        model = AutoModelForCausalLM.from_pretrained(a.base, torch_dtype=dtype, **kw)
    model.config.use_cache = False
    if not a.no_4bit:
        model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    elif cuda:
        model.gradient_checkpointing_enable()
        model.enable_input_require_grads()
    cfg = LoraConfig(r=a.lora_r, lora_alpha=a.lora_alpha, lora_dropout=a.lora_dropout, bias="none", task_type="CAUSAL_LM",
                     target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]
                     if not a.base.endswith("tiny-gpt2") else ["c_attn"])
    model = get_peft_model(model, cfg)
    model.print_trainable_parameters()

    train, sk = load_rows(a.train, tok, a.max_seq, a.limit)
    val, skv = load_rows(a.val, tok, a.max_seq, 40) if os.path.exists(a.val) else ([], 0)
    print(f"train examples: {len(train)} (skipped {sk} over {a.max_seq} tokens); val examples: {len(val)}")
    if not train:
        raise SystemExit("no training examples; run training/prep_data.py first")

    steps_per_epoch = math.ceil(len(train) / (a.batch * a.grad_accum))
    args = dict(output_dir=os.path.join(a.out, "_ckpt"), num_train_epochs=a.epochs, max_steps=a.max_steps,
                per_device_train_batch_size=a.batch, per_device_eval_batch_size=a.batch,
                gradient_accumulation_steps=a.grad_accum, learning_rate=a.lr, lr_scheduler_type="cosine",
                warmup_steps=max(1, int(0.05 * steps_per_epoch * a.epochs)), weight_decay=0.0, logging_steps=5,
                save_strategy="no", report_to="none", fp16=(dtype == torch.float16), bf16=bf16, seed=a.seed,
                gradient_checkpointing=cuda, remove_unused_columns=False,
                optim="paged_adamw_8bit" if not a.no_4bit else "adamw_torch", use_cpu=not cuda)
    if val:
        args["eval_strategy" if "eval_strategy" in TrainingArguments.__dataclass_fields__ else "evaluation_strategy"] = "epoch"
    try:
        targs = TrainingArguments(**args)
    except TypeError as e:  # a renamed option in some transformers version: drop it and warn
        print("warning:", e)
        for k in ("warmup_steps",):
            args.pop(k, None)
        targs = TrainingArguments(**args)
    trainer = Trainer(model=model, args=targs, train_dataset=train, eval_dataset=val or None, data_collator=Collator(tok.pad_token_id))
    trainer.train()
    os.makedirs(a.out, exist_ok=True)
    model.save_pretrained(a.out)
    tok.save_pretrained(a.out)
    json.dump({"base": a.base, "args": vars(a), "log": trainer.state.log_history}, open(os.path.join(a.out, "train_log.json"), "w"), indent=1)
    print("saved adapter to", a.out)


if __name__ == "__main__":
    main()
