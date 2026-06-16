import re


SUSPICIOUS_KEYWORDS = [
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "auth", "credential", "bearer", "access_key"
]

def analyze_context(line: str, match_group: str) -> int:
    """
    Phân tích ngữ cảnh xung quanh chuỗi ký tự bị nghi ngờ.
    Trả về điểm rủi ro (Risk Score). Điểm càng cao càng nguy hiểm.
    """
    risk_score = 0
    line_lower = line.lower()
    
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in line_lower:
            
            risk_score += 2
            
   
    if re.search(r"=\s*['\"]?" + re.escape(match_group), line):
        risk_score += 3
        
    return risk_score
