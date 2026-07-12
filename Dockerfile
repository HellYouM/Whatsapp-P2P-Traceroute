FROM python:3.12-slim

# libpcap for scapy capture; tini for clean signal handling.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 tini && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Capture needs host networking + NET_RAW/NET_ADMIN:
#   docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN \
#     -p 8000:8000 wit --dashboard
ENTRYPOINT ["tini", "--", "python", "main.py"]
CMD ["--dashboard"]
