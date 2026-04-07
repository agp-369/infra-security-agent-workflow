# Standard Dockerfile for OpenEnv Submission
FROM python:3.10-slim

WORKDIR /app

# Copy the entire project root
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Environment variable for python to find our packages
ENV PYTHONPATH=/app

# HF Mandatory Port
EXPOSE 7860

# Point to our new standardized app location
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]
