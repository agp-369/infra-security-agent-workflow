# Finalist-Grade Dockerfile
FROM python:3.10-slim

WORKDIR /app

# 1. Install system dependencies
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# 2. Copy code
COPY . /app

# 3. Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 4. Set Python path so it finds our 'src' folder
ENV PYTHONPATH=/app/src

# 5. HF Port
EXPOSE 7860

# 6. Launch standardized server
CMD ["uvicorn", "infra_security_agent.server.app:app", "--host", "0.0.0.0", "--port", "7860"]
