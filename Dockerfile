FROM python:3.11-slim

# Set working directory
WORKDIR /usr/src/app

# NEW: Install OS dependencies for psutil
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install requirements
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

EXPOSE 5000

# CMD is perfect - Gunicorn is the right choice for production
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]