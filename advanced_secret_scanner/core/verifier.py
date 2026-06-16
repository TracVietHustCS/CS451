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

# import boto3
# from botocore.exceptions import ClientError

# def verify_aws_key(access_key: str) -> bool:
#     """
#     Kiểm tra xem AWS Access Key ID có thực sự tồn tại hay không.
#     Sử dụng một secret key giả mạo. Nếu lỗi trả về là 'SignatureDoesNotMatch',
#     điều đó có nghĩa là Access Key có tồn tại (chỉ là sai chữ ký).
#     Nếu lỗi là 'InvalidClientTokenId', Access Key không tồn tại.
#     """
#     try:
#         client = boto3.client(
#             'sts',
#             aws_access_key_id=access_key,
#             aws_secret_access_key='dummy_secret_for_validation_purposes_only',
#             region_name='us-east-1'
#         )
#         client.get_caller_identity()
#     except ClientError as e:
#         error_code = e.response.get('Error', {}).get('Code')
#         if error_code == 'SignatureDoesNotMatch':
#             return True
#         elif error_code == 'InvalidClientTokenId':
#             return False
#     except Exception:
#         pass
#     return False

def verify_gitlab_token(token: str) -> bool:
    """
    Ping API GitLab để kiểm tra xem token glpat- còn hiệu lực hay không.
    """
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get("https://gitlab.com/api/v4/user", headers=headers, timeout=5)
        if response.status_code == 200:
            return True
    except requests.RequestException:
        pass
    return False

def verify_secret(secret_type: str, secret_value: str) -> str:
    """
    Thực hiện Active Verification.
    Trả về 'ACTIVE' (cực kỳ nguy hiểm), 'INVALID' (cảnh báo giả), hoặc 'UNKNOWN' (không hỗ trợ verify).
    """
    if secret_type == "github":
        is_active = verify_github_token(secret_value)
        return "ACTIVE" if is_active else "INVALID"
    elif secret_type == "gitlab":
        is_active = verify_gitlab_token(secret_value)
        return "ACTIVE" if is_active else "INVALID"
    # elif secret_type == "aws":
    #     is_active = verify_aws_key(secret_value)
    #     return "ACTIVE" if is_active else "INVALID"
        
    # Có thể mở rộng thêm cho các loại key khác
    return "UNKNOWN"
