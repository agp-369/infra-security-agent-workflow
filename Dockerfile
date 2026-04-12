# Standard Dockerfile for OpenEnv Submission
FROM python:3.10-slim

WORKDIR /app

# 1. Copy code
COPY . /app

# 2. Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 3. Set Python path
ENV PYTHONPATH=/app

# 4. HF Mandatory Port
EXPOSE 7860

# 5. Launch standardized server
CMD ["uvicorn", "env.server.app:app", "--host", "0.0.0.0", "--port", "7860"]
