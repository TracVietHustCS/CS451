import math
from collections import Counter

def shannon_entropy(data: str) -> float:
    """
    Tính Shannon Entropy của một chuỗi.
    Độ ngẫu nhiên càng cao (mật khẩu mạnh, mã hóa), entropy càng cao.
    """
    if not data:
        return 0
    entropy = 0
    length = len(data)
    counts = Counter(data)
    
    for count in counts.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
        
    return entropy

def is_suspicious_entropy(data: str, threshold: float = 4.5) -> bool:
    """
    Kiểm tra xem chuỗi có entropy vượt ngưỡng đáng ngờ hay không.
    Ngưỡng 4.5 thường hiệu quả với chuỗi > 16 ký tự.
    """
    # Chỉ kiểm tra các chuỗi đủ dài để tránh false positive ở các từ ngắn
    if len(data) < 16:
        return False
    return shannon_entropy(data) >= threshold
