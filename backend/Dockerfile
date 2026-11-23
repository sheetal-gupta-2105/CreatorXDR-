FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    tesseract-ocr-hin \
    poppler-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt ./requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

RUN mkdir -p /app/storage/identity_documents \
    && useradd --create-home appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 5001

CMD ["sh", "-c", "flask --app run db upgrade && gunicorn --bind 0.0.0.0:5001 --workers 2 --threads 4 --timeout 120 run:app"]
