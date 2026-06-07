import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

def send_alert(findings: list):
    """
    Gửi báo cáo qua Email nếu có lỗi nghiêm trọng.
    """
    if not findings:
        return
        
    smtp_user = "quest7273@gmail.com"
    smtp_pass = os.environ.get("SMTP_PASS")
    receiver_email = os.environ.get("ALERT_EMAIL")
    
    if not smtp_pass or not receiver_email:
        print("[!] Thiếu cấu hình Email (SMTP_PASS, ALERT_EMAIL). Bỏ qua việc gửi alert.")
        return

    
    critical_findings = [f for f in findings if f['risk_score'] >= 5 or f['status'] == 'ACTIVE']
    
    if not critical_findings:
        return

    # 1. Định dạng nội dung thư (HTML)
    html_content = "<h2>🚨 CẢNH BÁO: Phát hiện Secret bị lộ trong CI/CD!</h2><ul>"
    for f in critical_findings[:10]: # Giới hạn gửi 10 lỗi để tránh bị dài dòng
        html_content += f"""
            <li>
                <strong>Loại Secret:</strong> {f['secret_name']} <br>
                <strong>Trạng thái:</strong> <span style="color:red">{f['status']}</span> <br>
                <strong>File:</strong> {f['file']} (Dòng {f['line_num']}) <br>
                <strong>Mã bị lộ:</strong> <code>{f['matched_snippet']}</code>
            </li><hr>
        """
    html_content += "</ul><p>Pipeline CI/CD đã tự động bị chặn. Vui lòng kiểm tra và vô hiệu hóa key bị lộ ngay lập tức!</p>"

    # 2. Xây dựng gói thư (MIME)
    msg = MIMEMultipart()
    msg['From'] = f"Vault Eye <{smtp_user}>"
    msg['To'] = receiver_email
    msg['Subject'] = "[Khẩn cấp] Cảnh báo Bảo mật Secret Scanner"
    msg.attach(MIMEText(html_content, 'html'))

    # 3. Gửi thư qua máy chủ Gmail
    try:
        print("[*] Đang kết nối tới máy chủ Email...")
        # Sử dụng port 587 (TLS) của Google
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls() # Mã hóa đường truyền
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        print("[+] Đã gửi Email cảnh báo thành công!")
    except Exception as e:
        print(f"[-] Lỗi khi gửi Email: {e}")
