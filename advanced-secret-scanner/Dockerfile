# Sử dụng Python image mỏng gọn
FROM python:3.10-slim

# Cài đặt Git để thư viện GitPython có thể hoạt động
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Thiết lập thư mục làm việc trong container
WORKDIR /app

# Copy các file cần thiết
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ mã nguồn công cụ
COPY . .

# Điểm đầu vào (Entrypoint) cho Jenkins chạy
ENTRYPOINT ["python", "/app/scanner.py"]
