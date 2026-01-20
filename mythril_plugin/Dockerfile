FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    libc-dev \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip setuptools wheel

RUN pip install \
    mythril==0.24.8 \
    flask

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 5000
CMD ["python", "server.py"]
