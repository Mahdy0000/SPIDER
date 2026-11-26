#!/usr/bin/env bash
# Merged Hugging Face model dir -> GGUF -> quantized GGUF -> Ollama model.
#
#   training/convert_to_ollama.sh training/out/merged                 # Q4_K_M, model name spider-reviewer
#   training/convert_to_ollama.sh training/out/merged Q8_0            # higher fidelity, ~3.4 GB
#   training/convert_to_ollama.sh training/out/merged Q4_K_M my-name
#   SKIP_OLLAMA=1 training/convert_to_ollama.sh training/out/merged   # only produce the .gguf (e.g. on Colab)
#
# Needs: git, cmake + a C++ compiler (only to build llama-quantize), python3 with `pip install gguf torch transformers sentencepiece`.
# Set LLAMA_CPP=/path/to/llama.cpp to reuse an existing checkout. The tool name "spider-reviewer" is what
# spider looks for automatically (see "Default model" in the README).
set -euo pipefail

MERGED="${1:?usage: $0 MERGED_MODEL_DIR [QUANT] [OLLAMA_NAME]}"
QUANT="${2:-Q4_K_M}"
NAME="${3:-spider-reviewer}"
HERE="$(cd "$(dirname "$0")" && pwd)"
LLAMA_CPP="${LLAMA_CPP:-$HERE/out/llama.cpp}"
OUT="${OUT:-$HERE/out}"
mkdir -p "$OUT"

if [ ! -d "$LLAMA_CPP" ]; then
  git clone --depth 1 https://github.com/ggml-org/llama.cpp "$LLAMA_CPP"
fi
pip install -q gguf sentencepiece protobuf >/dev/null

F16="$OUT/spider-reviewer.f16.gguf"
python3 "$LLAMA_CPP/convert_hf_to_gguf.py" "$MERGED" --outfile "$F16" --outtype f16

FINAL="$OUT/spider-reviewer.$QUANT.gguf"
case "$QUANT" in
  F16|f16) FINAL="$F16" ;;
  *)
    QBIN="$(command -v llama-quantize || true)"
    [ -z "$QBIN" ] && [ -x "$LLAMA_CPP/build/bin/llama-quantize" ] && QBIN="$LLAMA_CPP/build/bin/llama-quantize"
    if [ -z "$QBIN" ]; then
      cmake -S "$LLAMA_CPP" -B "$LLAMA_CPP/build" -DGGML_NATIVE=OFF -DLLAMA_CURL=OFF -DCMAKE_BUILD_TYPE=Release
      cmake --build "$LLAMA_CPP/build" --target llama-quantize -j "$(nproc)"
      QBIN="$LLAMA_CPP/build/bin/llama-quantize"
    fi
    "$QBIN" "$F16" "$FINAL" "$QUANT"
    ;;
esac
echo "GGUF ready: $FINAL ($(du -h "$FINAL" | cut -f1))"

sed "s#^FROM .*#FROM ./$(basename "$FINAL")#" "$HERE/Modelfile" > "$OUT/Modelfile"
echo "Modelfile written: $OUT/Modelfile"

if [ "${SKIP_OLLAMA:-0}" = "1" ]; then
  echo "Skipping 'ollama create'. On the machine with Ollama run:  cd $OUT && ollama create $NAME -f Modelfile"
  exit 0
fi
(cd "$OUT" && ollama create "$NAME" -f Modelfile)
echo "Done. Try:  ollama run $NAME   or   python -m spider tests/fixtures/vulnerable_app.py"
