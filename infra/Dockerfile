# Dockerfile for InfraHash Flask App
FROM python:3.11-slim

WORKDIR /app

# Copy dependency file first (for better caching)
COPY requirements.txt .

# Install all dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the app code
COPY infrahash.py /app/
COPY templates /app/templates

EXPOSE 5000

# Use Gunicorn for production (optional but better)
# CMD ["gunicorn", "-b", "0.0.0.0:5000", "infrahash:app"]

# For local/simple startup:
CMD ["python", "infrahash.py"]
