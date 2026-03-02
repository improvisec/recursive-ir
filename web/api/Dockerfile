FROM python:3.12-slim

WORKDIR /app

# libzstd.so.1 for ctypes (zstd compression in main.py)
RUN apt-get update \
 && apt-get install -y --no-install-recommends libzstd1 \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
