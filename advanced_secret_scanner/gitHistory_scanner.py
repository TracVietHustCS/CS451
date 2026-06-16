import os
import sys
import argparse
import requests
# Adjust this import depending on your root directory execution
from core.regex_engine import RegexEngine 
from reporter import send_alert

def main():
    # Setup dynamic path for rules.json
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_rules = os.path.join(script_dir, "rules.json")

    # Command-line arguments
    parser = argparse.ArgumentParser(description="Advanced DevSecOps Secret Scanner for GitHub Commits")
    parser.add_argument("--owner", required=True, help="GitHub Repository Owner (e.g., TracVietHustCS)")
    parser.add_argument("--repo", required=True, help="GitHub Repository Name (e.g., CS451)")
    parser.add_argument("--branch", default="main", help="Branch name to scan (default: main)")
    parser.add_argument("--rules", default=default_rules, help="Path to rules.json")
    parser.add_argument("--token", help="GitHub Personal Access Token (defaults to MY_TOKEN env var)")
    
    args = parser.parse_args()

    OWNER = args.owner
    REPO = args.repo
    BRANCH = args.branch
    RULES_PATH = args.rules
    TOKEN = args.token or os.environ.get("MY_TOKEN")

    if not TOKEN:
        print("[-] Lỗi: Cần có GitHub token. Sử dụng --token hoặc biến môi trường MY_TOKEN.")
        sys.exit(1)

    if not os.path.exists(RULES_PATH):
        print(f"[-] Lỗi: Không tìm thấy file rules tại {RULES_PATH}.")
        sys.exit(1)

    print(f"[*] Đang khởi động GitHub Commit Scanner cho: {OWNER}/{REPO} (Branch: {BRANCH})")

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"Bearer {TOKEN}",
    }

    url = f"https://api.github.com/repos/{OWNER}/{REPO}/commits?sha={BRANCH}"
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"[-] Lỗi khi fetch commits: Mã {response.status_code} - {response.text}")
        sys.exit(1)

    commits = response.json()
    all_shas = [(commit["sha"], commit["commit"]["author"]["date"]) for commit in commits]
    
    print(f"[*] Tìm thấy {len(all_shas)} commits. Đang quét patches...\n")

    engine = RegexEngine(RULES_PATH)
    all_findings = []

    # Iterate through commits (oldest to newest)
    for index, sha_info in enumerate(all_shas[::-1]):
        sha, date = sha_info
        commit_url = f"https://api.github.com/repos/{OWNER}/{REPO}/commits/{sha}"
        commit_response = requests.get(commit_url, headers=headers)
        
        if commit_response.status_code == 200:
            commit = commit_response.json()
            files = commit.get("files", [])

            for file in files:
                patch = file.get("patch")
                filename = file.get("filename", "unknown_file")

                if not patch:
                    continue

                # Split the patch into lines for accurate contextual scanning
                lines = patch.split('\n')
                for line_num, line in enumerate(lines, start=1):
                    # Only scan newly added code, ignore deletions or context
                    if line.startswith('+') and not line.startswith('+++'):
                        clean_line = line[1:] # Strip the '+' character
                        file_context = f"{filename} (Commit: {sha})"
                        
                        findings = engine.scan_line(clean_line, file_context, line_num)
                        if findings:
                            all_findings.extend(findings)
        else:
            print(f"[-] Lỗi khi fetch commit {sha}: {commit_response.status_code}")

    # Process and report the gathered findings
    if not all_findings:
        print("[+] Tuyệt vời! Không phát hiện Secret nào bị lộ trong lịch sử commit.")
        sys.exit(0)

    print(f"\n[!] PHÁT HIỆN {len(all_findings)} VẤN ĐỀ BẢO MẬT TỪ GITHUB:\n")
    critical_count = 0
    
    for idx, f in enumerate(all_findings, start=1):
        print(f"{idx}. [{f['status']}] {f['secret_name']} (Risk: {f['risk_score']})")
        print(f"   - Nguồn: {f['file']}")
        print(f"   - Dòng Patch: {f['line_num']}")
        print(f"   - Mã bị lộ: {f['matched_snippet']}\n")
        
        if f['risk_score'] >= 5 or f['status'] == 'ACTIVE':
            critical_count += 1

    if critical_count > 0:
        print(f"[*] Đang gửi Alert cho {critical_count} lỗi nghiêm trọng...")
        send_alert(all_findings)
        print("[-] Quá trình quét thất bại (Failed) để bảo vệ hệ thống. Vui lòng xử lý các Secret bị lộ.")
        sys.exit(1)
    else:
        print("[*] Các lỗi phát hiện có rủi ro thấp. Quá trình quét được phép đi tiếp.")
        sys.exit(0)

if __name__ == "__main__":
    main()