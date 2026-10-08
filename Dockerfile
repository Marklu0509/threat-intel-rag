# Demo API image (grill-decisions Q49). The passages and index must be the v0.1.0 evaluation
# build: CI downloads them from the GitHub Release and checks SHA-256 before this build runs.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    HF_HOME=/opt/hf TOKENIZERS_PARALLELISM=false HF_HUB_OFFLINE=0
WORKDIR /app

# 1. CPU-only torch: the default PyPI wheel for amd64 bundles CUDA libraries (several GB)
RUN pip install --index-url https://download.pytorch.org/whl/cpu "torch==2.14.1"

# 2. The other pinned dependencies, read from pyproject.toml so versions live in one place
COPY pyproject.toml ./
RUN python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']))" \
      > /tmp/requirements.txt && pip install -r /tmp/requirements.txt

# 3. bge-m3 baked into the image, so a cold start never downloads it (Q44). The repo ships its
#    weights twice: pytorch_model.bin (what sentence-transformers loads) and an ONNX export
#    (onnx/, another 2.27 GB). Skip the ONNX copy; the load check runs offline to prove nothing
#    needed is missing.
RUN python -c "from huggingface_hub import snapshot_download; snapshot_download('BAAI/bge-m3', ignore_patterns=['onnx/*'])" \
 && HF_HUB_OFFLINE=1 python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('BAAI/bge-m3')"
ENV HF_HUB_OFFLINE=1

# 4. Data and code change most often, so they come last
COPY data/processed ./data/processed
COPY data/index ./data/index
COPY src ./src
# Only the index needs to be writable (Chroma records each client that opens it). The model stays
# root-owned and read-only: chown on it would copy all 2.3 GB into a new layer.
RUN pip install --no-deps -e . \
 && useradd --create-home --uid 10001 app && chown -R app /app/data/index
USER app

# The commit this image was built from; /health reports it so a deploy can confirm it's live
ARG GIT_SHA=dev
ENV ATTACK_QA_SERVE=1 APP_VERSION=$GIT_SHA
EXPOSE 8000
CMD ["uvicorn", "attack_qa.web.main:app", "--host", "0.0.0.0", "--port", "8000"]
