# Cloud + Local Inference Options (GGUF)

Objective
- Cloud and local run must use this exact GGUF:
  https://huggingface.co/Mungert/Dolphin-Mistral-24B-Venice-Edition-GGUF/resolve/main/Dolphin-Mistral-24B-Venice-Edition-iq1_m.gguf
- Local run: approximately 7GB download; runnable via llama.cpp server. vLLM is provided as an optional alternative, but requires Transformers weights (GGUF not supported by vLLM).

Quick start — Cloud (Docker Compose)
1) Copy .env.sample to .env and fill HF_TOKEN (if required) and API_KEY.
2) Run: docker compose up -d
3) Test:
   curl -s -H "Authorization: Bearer $API_KEY" -H 'Content-Type: application/json' \
     -d '{"model":"local","messages":[{"role":"user","content":"Say hello"}]}' \
     http://localhost:8000/v1/chat/completions

Quick start — Local (no Docker, minimal)
- Requires Python 3.11+, gcc, CMake, and llama-cpp-python build environment.
- One-time 7GB download to ./models/model.gguf.
1) ./scripts/local_download.sh
2) python3 -m venv .venv && source .venv/bin/activate
3) pip install -r server/requirements.txt
4) export API_KEY=dev-local
5) python3 -m llama_cpp.server --model ./models/model.gguf --port 8000 --api_key "$API_KEY"
6) Use the same curl test as above.

Alternate — Local via Compose
- Uses the same image and downloader as cloud:
  docker compose -f docker-compose.yml --profile local up -d

Optional vLLM (Transformers weights only; GGUF incompatible)
- If you need vLLM locally, use docker-compose.vllm.yml and set VLLM_MODEL_REPO to a compatible Transformers model (not GGUF). For Dolphin 24B, you must point to a repo providing standard Hugging Face Transformers weights (.safetensors). Example (placeholder):
  VLLM_MODEL_REPO=someorg/dolphin-mistral-24b-transformers
- Start:
  HF_TOKEN=... docker compose -f docker-compose.vllm.yml up -d
- Endpoint: http://localhost:8001/v1/chat/completions (OpenAI-compatible)

Configuration
- MODEL_URL (default set to the exact iq1_m.gguf you requested) — direct download to /models/model.gguf
- REPO_ID and MODEL_FILE — snapshot fallback if MODEL_URL is unset
- API_KEY — required for server access
- THREADS, N_CTX, N_GPU_LAYERS — performance tuning

Security
- Put the cloud endpoint behind HTTPS and a WAF/proxy.
- Do not hardcode API keys into the APK. The sample APK stores credentials in EncryptedSharedPreferences.

Rationale
- GGUF → llama.cpp is the correct runtime; vLLM cannot load GGUF. We keep your exact model file for both cloud and local. vLLM option provided separately for compatible Transformers weights.

References
- /reference/External_Libraries.md
- /reference/Model_Compatibility.md
- llama-cpp-python (OpenAI server) — https://github.com/abetlen/llama-cpp-python
- vLLM (OpenAI server) — https://github.com/vllm-project/vllm
