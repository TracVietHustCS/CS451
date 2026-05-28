import argparse
import sys
import os
from core.dir_scanner import DirectoryScanner
from reporter import send_alert

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_rules = os.path.join(script_dir, "rules.json")
    
    parser = argparse.ArgumentParser(description="Advanced DevSecOps Secret Scanner for CI/CD")
    parser.add_argument("--path", required=True, help="Đường dẫn thư mục mã nguồn cần quét")
    parser.add_argument("--rules", default=default_rules, help="Đường dẫn file rules.json")
    
    args = parser.parse_args()
    
    scan_path = args.path
    rules_path = args.rules
    
    if not os.path.exists(scan_path):
        print(f"Lỗi: Thư mục {scan_path} không tồn tại.")
        sys.exit(1)
        
    print(f"[*] Đang khởi động Secret Scanner cho thư mục: {scan_path}")
    
    
    scanner = DirectoryScanner(scan_path, rules_path)
    findings = scanner.scan_all()
    
    if not findings:
        print("[+] Tuyệt vời! Không phát hiện Secret nào bị lộ.")
        sys.exit(0) 
        
    print(f"\n[!] PHÁT HIỆN {len(findings)} VẤN ĐỀ BẢO MẬT:\n")
    critical_count = 0
    for idx, f in enumerate(findings, start=1):
        print(f"{idx}. [{f['status']}] {f['secret_name']} (Risk: {f['risk_score']})")
        print(f"   - File: {f['file']}")
        print(f"   - Dòng: {f['line_num']}")
        print(f"   - Mã bị lộ: {f['matched_snippet']}\n")
        
        if f['risk_score'] >= 5 or f['status'] == 'ACTIVE':
            critical_count += 1
            

    if critical_count > 0:
        print(f"[*] Đang gửi Alert cho {critical_count} lỗi nghiêm trọng...")
        send_alert(findings)
        print("[-] Pipeline sẽ bị đánh trượt (Failed) để bảo vệ hệ thống.")
        sys.exit(1) 
    else:
        print("[*] Các lỗi phát hiện có rủi ro thấp (Có thể là cảnh báo giả). Pipeline được phép đi tiếp.")
        sys.exit(0)

if __name__ == "__main__":
    main()
