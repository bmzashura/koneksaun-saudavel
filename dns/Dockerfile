FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy blocklist update script
COPY update_blocklist.py .

# Create directories
RUN mkdir -p /app/blocklists /app/logs

# Default blocklists (will be downloaded on first run)
ENV BLOCKLIST_ADS_URL="https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt"
ENV BLOCKLIST_PORN_URL="https://github.com/blocklistproject/Lists/raw/master/lists/porn-all.txt"
ENV BLOCKLIST_GAMBLE_URL="https://github.com/blocklistproject/Lists/raw/master/lists/gambling-all.txt"

# Run blocklist update then DNS server
CMD ["python", "-c", "import subprocess; subprocess.run(['python', 'update_blocklist.py']); import dns_server; dns_server.run()"]
