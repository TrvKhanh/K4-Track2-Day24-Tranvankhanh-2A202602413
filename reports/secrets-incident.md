# Secret giả trong lịch sử Git — checkpoint 4

- Scanner và phiên bản: Gitleaks v8.30.1
- Commit chứa token giả: `1bdd849`
- File, rule và kết quả quét lịch sử: `.gitleaks.toml` định nghĩa rule `lab24-synthetic-token`; quét lịch sử bằng `gitleaks git --config .gitleaks.toml .` dự kiến báo 1 finding ở commit này.
- Kết quả quét file hiện tại: `gitleaks dir --config .gitleaks.toml .` phải sạch vì token giả không còn ở HEAD.
- Nếu đây là credential thật, cần xử lý thế nào: thu hồi/rotate ngay, xoá khỏi mọi branch/tag, và xem lại CI/logs/artifacts, vì secret đã lộ cần không chỉ xoá file khỏi HEAD.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ: pin dependency và hook giúp ngăn drift và phát hiện sớm, nhưng không làm mất hiệu lực của token đã có trong lịch sử git; khôi phục bảo mật đòi hỏi rotate và kiểm tra toàn bộ môi trường.
