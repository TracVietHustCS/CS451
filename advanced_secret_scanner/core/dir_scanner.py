import os
from core.regex_engine import RegexEngine

class DirectoryScanner:
    def __init__(self, scan_path: str, rules_path: str):
        self.scan_path = scan_path
        self.engine = RegexEngine(rules_path)

    def scan_all(self) -> list:
        print(f"[*] Đang quét toàn bộ file trong thư mục: {self.scan_path}...")
        all_findings = []
        for root, _, files in os.walk(self.scan_path):
            for file in files:
                # Bỏ qua file tĩnh, file binary hoặc thư mục .git
                if file.endswith(('.png', '.jpg', '.jpeg', '.pdf', '.zip')) or ".git" in root:
                    continue
                    
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        
                    for line_num, line in enumerate(lines, start=1):
                        findings = self.engine.scan_line(line, filepath, line_num)
                        all_findings.extend(findings)
                except Exception:
                    pass
                    
        return all_findings