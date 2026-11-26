# Fine-tuning the SPIDER reviewer

Goal: a model that answers SPIDER's code-review prompt in the tool's JSON, with fewer wrong or invented findings than the stock model, and that you run locally through Ollama. Defensive review only: training targets are findings, explanations and fixed code, never exploits.

## What is verified and what is not

Verified on a CPU box (no GPU): `prep_data.py` output (schema, line spans, splits, leakage guard, 43 unit tests), the training loop end to end on a tiny model (`sshleifer/tiny-gpt2`, 3 steps, loss logged, adapter saved), adapter merge, tokenisation and label masking with the real Llama 3.2 tokenizer (one BOS, loss only on the answer, `<|eot_id|>` ends the answer, 849 of 851 examples fit 2048 tokens), HF to GGUF conversion (f16 and q8_0) on a small Llama-architecture model, the default-model lookup in the tool.

**Only your run proves:** that 4-bit QLoRA fits and trains on a T4 with the 3B model (expected, not seen), training time, the quality of the resulting model, `llama-quantize` + `ollama create` on the real 3B model (I built the scripts from the documented steps; the quantize build did not finish on the 1-core test box), and any before/after improvement. The expected gain is "better format and fewer false alarms on code like the training data", not a better general hacker.

## Base model

The tool's default `dolphinlabs/llama3.2-3b-uncensored` is an Ollama upload; its page says it is Meta's Llama 3.2 3B Instruct with refusal behaviour removed by abliteration, no fine-tuning. It names no Hugging Face repo. The closest public match is `chuanli11/Llama-3.2-3B-Instruct-uncensored` (same description of method, ungated), used as the default here. That it is byte-identical to the Ollama build is **not confirmed**. Change it with `--base`, for example the gated `meta-llama/Llama-3.2-3B-Instruct` (needs an HF token and accepted licence) or `huihui-ai/Llama-3.2-3B-Instruct-abliterated`. Llama 3.2 licence applies to the result.

## 1. Data (`prep_data.py`)

```bash
python dataset/merge.py                 # optional, prep_data also reads the shards directly
python training/prep_data.py            # -> training/data/{train,val}.jsonl + stats.json
```

About 850 training and 110 validation examples. Task mix, all built with the real `spider.prompt`, `spider.knowledge` and `spider.verify` code so training matches serving:

| kind | what | purpose |
|---|---|---|
| review | numbered file -> `{"findings": [...]}` | the SAST prompt |
| review_multi | several short snippets in one file, several findings | closer to real files |
| review_clean | the fixed code -> `{"findings": []}` | stay quiet on fixed code |
| verify_real / verify_fp | the `--verify` prompt on vulnerable / fixed code | keeps `--verify` working |
| explain, fix | free text (only with `--extra-tasks`) | optional |

How dataset problems are handled: heuristic CyberNative labels are capped per OWASP category (60), marked `confidence: "medium"`; missing CWE stays `""` (nothing is invented); no-OWASP rows get `owasp: "N/A"`; Juice Shop "vulnerable" code is an incorrect candidate fix, so its note is used as the description; 87 rows with stray non-Latin characters, overlong rows and rows with no code change are dropped; Juliet is capped at 30 because its `bad`/`good` names are a shortcut; any row sharing a line with `tests/fixtures` or `benchmark/` is excluded so the benchmark is not trained on. Line numbers come from diffing vulnerable vs fixed code (first changed region, at most 12 lines), and the target `fixed_code` replaces exactly those lines, as `--patch` does. Severity is a coarse per-category prior because the dataset has none. These labels are noisy: the model learns this dataset's view, including its mistakes.

Not covered: the web agent loop prompts (`spider web --agent`) have no training data. A LoRA with a low rank usually keeps general instruction following, but check `--agent` with the tuned model, and use `--model <stock model>` for it if it gets worse.

## 2. Train on Colab (free T4)

Open `training/spider_finetune_colab.ipynb` in Colab (File > Open notebook > GitHub > `Mahdy0000/SPIDER`), set Runtime to T4 GPU, run all cells. It installs dependencies, builds the data, trains, merges, converts to GGUF (Q4_K_M) and copies the files to Google Drive.

Defaults (`train_qlora.py --help`): 4-bit NF4 + double quantisation, LoRA r=16 / alpha 32 on all attention and MLP projections, 3 epochs, lr 2e-4 cosine, 2048-token window, batch 1 x 16 accumulation, fp16 (a T4 has no bf16), gradient checkpointing, 8-bit paged AdamW. Out of memory: `--max-seq 1536` or `--lora-r 8`. Over-fitting signs: validation loss rising while train loss falls after epoch 1-2; use `--epochs 2`.

Local GPU instead: an NVIDIA card with about 10 GB VRAM or more (QLoRA of a 3B model at 2048 tokens), CUDA PyTorch, `pip install transformers peft accelerate bitsandbytes sentencepiece gguf`, then run the same three commands the notebook runs. No GPU: CPU training of a 3B model is impractical; use Colab. Apple Silicon: bitsandbytes 4-bit is not supported, so use Colab or MLX separately.

## 3. GGUF and Ollama

```bash
python training/merge_export.py --adapter training/out/adapter --out training/out/merged
bash training/convert_to_ollama.sh training/out/merged Q4_K_M       # needs ollama on this machine, else SKIP_OLLAMA=1
```

On Colab use `SKIP_OLLAMA=1`, then on your PC put `spider-reviewer.Q4_K_M.gguf` and `Modelfile` in one folder and run `ollama create spider-reviewer -f Modelfile`. The Modelfile uses the same Llama 3 template as training, temperature 0 and `num_ctx 4096`.

Quantisation: **Q4_K_M** (about 2 GB, default, runs on CPU or 4 GB GPUs, small quality loss), **Q5_K_M** (about 2.3 GB), **Q8_0** (about 3.4 GB, nearly lossless, use if you have 6 GB+ free). Quantising can shave a little off the fine-tune's gains; run the evaluation on the quantised model you will actually use.

## 4. Make it the default

SPIDER now picks the model in this order: `--model`, `$SPIDER_MODEL`, an installed Ollama model named `spider-reviewer`, then `dolphinlabs/llama3.2-3b-uncensored`. So after `ollama create spider-reviewer` there is nothing to configure, and `--model` still overrides everything. `ollama rm spider-reviewer` brings back the stock default.

## 5. Evaluate before and after

```bash
ollama pull dolphinlabs/llama3.2-3b-uncensored
python training/evaluate.py --model dolphinlabs/llama3.2-3b-uncensored --label before
python training/evaluate.py --model spider-reviewer --label after
python training/evaluate.py --compare before after
```

Run `before` first, on the same machine and quantisation as `after`. Results go to `training/results/*.json` (commit them if you want a record). It runs `benchmark/cases.json` exactly like `benchmark/run.py`, plus the held-out validation prompts. **The benchmark is tiny: one file, 4 expected findings, so recall moves in 25-point steps.** The held-out set (about 90 vulnerable and 20 clean prompts) is larger, but it comes from the same sources as the training data and half of it has heuristic labels, so it shows fit to this dataset, not real-world recall. Neither is a security guarantee. To really judge it, review a few of your own projects before/after and read the findings.
