FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Railway injects $PORT at runtime; shell form expands it
CMD uvicorn server:app --host 0.0.0.0 --port $PORT
