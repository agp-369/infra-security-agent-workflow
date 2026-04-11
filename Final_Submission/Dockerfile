FROM python:3.10-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
EXPOSE 7860
CMD ["uvicorn", "infra_security_agent.server.app:app", "--host", "0.0.0.0", "--port", "7860"]
