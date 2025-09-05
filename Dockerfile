# syntax=docker/dockerfile:1

FROM python:3.11-slim

# Install Google Chrome (headless) and required system libs
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget gnupg ca-certificates \
    && mkdir -p /usr/share/keyrings \
    && wget -qO- https://dl.google.com/linux/linux_signing_key.pub \
       | gpg --dearmor > /usr/share/keyrings/google-linux-signing-key.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-linux-signing-key.gpg] https://dl.google.com/linux/chrome/deb/ stable main" \
       > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
         google-chrome-stable \
         fonts-liberation libasound2 libnss3 libxshmfence1 libgbm1 libu2f-udev \
    && rm -rf /var/lib/apt/lists/*

# Set Python env
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install Python dependencies first for caching
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy app source
COPY . ./

# Default runtime uses headless Chrome; all configuration via env vars
# Example required envs (set these in EasyPanel):
#   MAUPASS_USERNAME, MAUPASS_PASSWORD
#   SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_TABLE
# Optional: MAUPASS_ACTS_URL, MAUPASS_PAGE_LIMIT, etc.

CMD ["python", "-u", "maupass_scraper.py", "--headless"]
