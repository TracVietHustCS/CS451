# Hướng dẫn chi tiết: Advanced Secret Scanner

Tài liệu này giải thích chi tiết cấu trúc mã nguồn, ý nghĩa của từng file và cách thức để bạn có thể tự kiểm thử (test) dự án này trên máy cá nhân (Local) trước khi đưa lên Jenkins.

---

## 1. Giải thích chi tiết từng File mã nguồn

Dự án được chia làm 5 phân hệ lõi (trong thư mục `core/`) và các file điều phối nằm ở thư mục gốc.

### Thư mục `core/` (Lõi xử lý)

*   **`core/__init__.py`**
    *   *Chức năng:* File rỗng dùng để đánh dấu thư mục `core` là một gói (package) chuẩn của Python. Giúp các file khác có thể dùng lệnh `from core.abc import xyz`.

*   **`core/regex_engine.py`**
    *   *Chức năng:* Đây là động cơ quét cơ bản. Nó đọc từng dòng code và sử dụng Biểu thức chính quy (Regex) để tìm ra các khuôn mẫu giống với AWS Key hoặc API Token.
    *   *Điểm nhấn:* Nếu nó quét bằng Regex không thấy, nó sẽ gọi tiếp hàm từ `entropy.py` để tìm các chuỗi ngẫu nhiên. Sau đó nó gọi hàm từ `context.py` để lấy điểm rủi ro.

*   **`core/entropy.py`**
    *   *Chức năng:* Chứa thuật toán toán học **Shannon Entropy**.
    *   *Hoạt động:* Nếu thấy một chuỗi như `aBcD1234!@#$`, nó sẽ tính toán mức độ hỗn loạn. Nếu điểm Entropy cao hơn `4.5` (ngưỡng cảnh báo), nó sẽ đánh dấu chuỗi này là "Nghi ngờ mật khẩu/key bị lộ" dù không khớp bất kỳ Regex nào.

*   **`core/context.py`**
    *   *Chức năng:* Phân tích ngữ cảnh (Context).
    *   *Hoạt động:* File này giúp giảm báo động giả. Nếu tìm thấy một chuỗi đáng ngờ, nó sẽ nhìn sang trái, sang phải xem trong dòng đó có các từ khóa nhạy cảm như `password=`, `secret`, `bearer` hay không. Nếu có, nó sẽ cộng thêm điểm Risk Score.

*   **`core/verifier.py`**
    *   *Chức năng:* Hệ thống xác minh trực tiếp (Active Verification) - Tính năng "Ăn tiền" của dự án.
    *   *Hoạt động:* Khi Regex tìm thấy một GitHub Token, thay vì báo động ngay, hàm này sẽ tự động gọi HTTP GET Request (ping) lên server `api.github.com`. Nếu GitHub trả về 200 OK (nghĩa là token này có thể dùng để hack được thật), nó mới gửi báo động ĐỎ. Nếu là token giả/hết hạn, nó sẽ bỏ qua.

*   **`core/dir_scanner.py`**
    *   *Chức năng:* Duyệt qua tất cả các file tĩnh trong thư mục dự án.
    *   *Hoạt động:* Tự động quét toàn bộ mã nguồn, đọc từng dòng và bỏ qua các file không cần thiết (như ảnh, PDF, thư mục `.git`). Đưa từng dòng text cho `regex_engine.py` xử lý.

### Thư mục gốc (Điều phối)

*   **`rules.json`**
    *   File cấu hình chứa danh sách các mẫu Regex (AWS, GitHub, Generic API) để `regex_engine.py` có thể đọc và quét. Dễ dàng thêm bớt quy tắc mà không cần sửa code Python.

*   **`reporter.py`**
    *   Chịu trách nhiệm giao tiếp với hệ thống Chat của bạn. Nhận vào danh sách lỗi, format lại thành tin nhắn JSON (có nhúng màu sắc, tiêu đề, dòng lỗi) và gửi (POST) thẳng qua Discord/Slack Webhook.

*   **`scanner.py`**
    *   File điều hành chính (Main Script). Khi Jenkins gọi chương trình, file này sẽ chạy. Nó sẽ ra lệnh cho `git_scanner` bắt đầu quét, nhận kết quả, gọi `reporter.py` để gửi tin nhắn, và đặc biệt: Nếu có lỗi nghiêm trọng, nó gọi `sys.exit(1)` để **bắt Jenkins phải Failed/Đỏ pipeline**.

*   **`Dockerfile` & `requirements.txt`**
    *   Dùng để đóng gói ứng dụng này thành Container, đảm bảo mang lên server Jenkins hay môi trường nào cũng chạy mượt mà mà không lo thiếu thư viện.

---

## 2. Hướng dẫn chạy thử ở máy cá nhân (Local)

Để chạy thử, bạn không cần phải có Jenkins ngay. Bạn có thể kiểm thử trực tiếp bằng Terminal trên máy tính theo các bước sau:

### Bước 1: Mở Terminal tại thư mục dự án
Mở PowerShell hoặc Command Prompt và di chuyển (cd) vào đúng thư mục dự án:
```bash
cd D:\learnjava\advanced-secret-scanner
```

### Bước 2: Cài đặt thư viện Python
Đảm bảo máy bạn đã cài Python. Chạy lệnh sau để cài các thư viện cần thiết:
```bash
pip install -r requirements.txt
```

### Bước 3: Tạo một file "Mồi" để test
Hãy tạo một file tên là `test_code.py` nằm ngay trong thư mục này, và copy nội dung lộ liễu này vào:
```python
# Code demo
def login():
    github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz" # Key giả mạo
    db_password = "SuperSecretAndRandomPassword123!@#"       # Lỗi Entropy cao
    aws_key = "AKIAIOSFODNN7EXAMPLE"                          # Lỗi AWS Key
```

### Bước 4: Chạy Secret Scanner
Thực thi lệnh sau để bắt đầu quét chính thư mục hiện tại:
```bash
python scanner.py --path .
```

### Bước 5: Cấu hình Alert qua Discord (Tùy chọn)
Nếu bạn muốn test xem nó có bắn tin nhắn qua Webhook thật không, hãy làm như sau trên Terminal (PowerShell) trước khi chạy Bước 4:
```powershell
$env:WEBHOOK_URL="https://discord.com/api/webhooks/your-webhook-url-here"
python scanner.py --path .
```

Nếu công cụ hoạt động đúng, bạn sẽ thấy nó in ra cảnh báo chữ màu đỏ trên Terminal và Pipeline của bạn sẽ bị đánh trượt (mã lỗi `Exit 1`).
