import requests

def verify_github_token(token: str) -> bool:
    """
    Ping API GitHub để kiểm tra xem token ghp_ còn hiệu lực hay không.
    """
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get("https://api.github.com/user", headers=headers, timeout=5)
        
        if response.status_code == 200:
            return True
    except requests.RequestException:
        pass
    return False

def verify_aws_key(access_key: str) -> bool:
    """
    Lưu ý: Để verify AWS Key đầy đủ cần cả Secret Key. 
    Ở đây ta chỉ mô phỏng việc gọi API kiểm tra STS GetCallerIdentity.
    (Trong thực tế cần cài boto3, đoạn này mô phỏng để giảm phụ thuộc).
    """
    # Nếu là AWS_ACCESS_KEY_ID (AKIA...), rủi ro luôn được đánh giá cao
    # dù không ping trực tiếp được nếu thiếu Secret Key.
    return True

def verify_secret(secret_type: str, secret_value: str) -> str:
    """
    Thực hiện Active Verification.
    Trả về 'ACTIVE' (cực kỳ nguy hiểm), 'INVALID' (cảnh báo giả), hoặc 'UNKNOWN' (không hỗ trợ verify).
    """
    if secret_type == "github":
        is_active = verify_github_token(secret_value)
        return "ACTIVE" if is_active else "INVALID"
        
    # Có thể mở rộng thêm cho các loại key khác
    return "UNKNOWN"
