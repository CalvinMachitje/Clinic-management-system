# Dockerfile
FROM python:3.11-slim

# Set work directory
WORKDIR /app

# Install system dependencies (only what's needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (best caching)
COPY requirements.txt .

# Install Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy entire app
COPY . .

# Create uploads folder
RUN mkdir -p static/uploads

# Expose port
EXPOSE 5000

# Run the app
CMD ["gunicorn", "-b", "0.0.0.0:5000", "--timeout", "300", "--workers", "2", "script:app"]