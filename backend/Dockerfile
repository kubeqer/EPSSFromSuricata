FROM python:3.12-slim
LABEL authors="kubeqer"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app
WORKDIR /app
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml ./
RUN pip install uv && \
    uv pip install --system -e .
COPY src/ ./src/
RUN mkdir -p /var/log/suricata
CMD ["uv", "run", "python", "-m", "src.main"]