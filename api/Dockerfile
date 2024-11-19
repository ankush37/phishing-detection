FROM python:3.12-slim

WORKDIR /app
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src /app/src

EXPOSE 8000

ENV FLASK_APP=src/app.py
ENV FLASK_ENV=development
ENV PYTHONPATH=/app/src

CMD ["flask", "run", "--host=0.0.0.0", "--port=8000"]
