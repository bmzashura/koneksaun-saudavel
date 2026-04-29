FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data

# Run init DB + Flask
CMD ["python", "-c", "from app import init_db; init_db(); from app import app; app.run(host='0.0.0.0', port=8080)"]
