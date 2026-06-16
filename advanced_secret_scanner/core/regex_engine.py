import json
import re
import os
from core.entropy import is_suspicious_entropy
from core.context import analyze_context
from core.verifier import verify_secret

class RegexEngine:
    def __init__(self, rules_path: str):
        with open(rules_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.rules = data.get("rules", [])
        
    def scan_line(self, line: str, filepath: str, line_num: int) -> list:
        """
        Quét một dòng text, áp dụng Regex, Context và Active Verification.
        """
        findings = []
        regex_matches = [] # Lưu trữ toàn bộ chuỗi gốc đã bị Regex tóm
        
        # 1. Quét theo Regex Rules
        for rule in self.rules:
            matches = re.finditer(rule["regex"], line)
            for match in matches:
                matched_string = match.group(0)
                # Dùng extract group 1 nếu có (cho trường hợp Generic Key)
                if len(match.groups()) > 0:
                    matched_string = match.group(1)
                
                regex_matches.append(matched_string) # Ghi nhận chuỗi này đã bị tóm
                
                # Active Verification
                status = verify_secret(rule["type"], matched_string)
                if status == "INVALID":
                    continue # Bỏ qua key rác đã bị vô hiệu hóa
                    
                # Context Analysis
                risk_score = analyze_context(line, matched_string)
                if status == "ACTIVE":
                    risk_score += 10 # Key còn sống -> Cực kỳ nghiêm trọng
                
                findings.append({
                    "file": filepath,
                    "line_num": line_num,
                    "secret_name": rule["name"],
                    "status": status,
                    "risk_score": risk_score,
                    "matched_snippet": matched_string[:4] + "***" # Che giấu key khi log
                })
                
        # 2. Entropy Analysis (Tìm các chuỗi ngẫu nhiên không có trong Regex)
        # Tách các từ trong dòng
        words = re.findall(r"[\w\.\-\+]{16,}", line)
        for word in words:
            # Tránh quét trùng với kết quả Regex ở trên (so sánh chuỗi thật thay vì chuỗi bị che ***)
            already_found = any(word in rm or rm in word for rm in regex_matches)
            if not already_found and is_suspicious_entropy(word):
                risk_score = analyze_context(line, word)
                if risk_score > 0: # Chỉ báo động nếu vừa có entropy cao, vừa có ngữ cảnh đáng ngờ
                    findings.append({
                        "file": filepath,
                        "line_num": line_num,
                        "secret_name": "High Entropy String (Nghi ngờ mật khẩu)",
                        "status": "UNKNOWN",
                        "risk_score": risk_score + 5,
                        "matched_snippet": word[:4] + "***"
                    })
                    
        return findings
