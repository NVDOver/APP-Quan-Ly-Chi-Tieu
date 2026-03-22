# App Quản lý Chi tiêu Cá nhân

Version: 1.0.0

## 📋 Mô tả dự án

Ứng dụng quản lý chi tiêu cá nhân giúp người dùng:
- Ghi lại các khoản chi tiêu hàng ngày
- Theo dõi chi tiêu theo danh mục
- Phân tích chi tiêu qua báo cáo
- Lập ngân sách chi tiêu

## 👥 Thành viên nhóm

| STT | Họ & Tên | MSSV | Vai trò |
|-----|--------|------|---------|
| 01 | Hoàng Hữu Điền | 172100041 | Developer |
| 02 | Báo Ngọc Thiên Bảo | 1721031139 | Team Leader |
| 03 | Nguyễn Đình Hào | 1721031314 | Developer |
| 04 | Ninh Văn Dũng | 1721031229 | Developer |
| 05 | Trần Quốc Lâm | 1721030882 | Developer |

## 📦 Công nghệ sử dụng

- **Ngôn ngữ**: Python 3.x
- **Framework**: Flask / Tkinter (tuỳ chọn)
- **Database**: SQLite
- **Frontend**: HTML/CSS/JavaScript (nếu dùng web)

## 🚀 Cài đặt

### Yêu cầu
- Python 3.7+

### Bước cài đặt

```bash
# Clone repository
git clone <repository-url>

# Tạo virtual environment
python -m venv venv

# Kích hoạt virtual environment
# Windows
venv\Scripts\activate
# MacOS/Linux
source venv/bin/activate

# Cài đặt dependencies
pip install -r requirements.txt

# Chạy ứng dụng
python src/main.py
```

## 📖 Hướng dẫn sử dụng

### Các tính năng chính

1. **Ghi chi tiêu**
   - Nhập số tiền
   - Chọn danh mục
   - Ghi chú

2. **Xem báo cáo**
   - Tính tổng chi tiêu
   - Xem chi tiêu theo danh mục
   - Tạo biểu đồ

3. **Quản lý ngân sách**
   - Đặt mục tiêu chi tiêu
   - Cảnh báo vượt ngân sách

## 📁 Cấu trúc dự án

```
12_HoangHuuDien_172100041_Tuan1/
├── src/                    # Mã nguồn chính
├── docs/                   # Tài liệu kỹ thuật
├── tests/                  # Unit tests
├── README.md              # File này
├── LICENSE                # Giấy phép
├── .gitignore            # Loại trừ thư mục không cần commit
└── requirements.txt      # Danh sách dependencies
```

## 🤝 Quy trình phát triển

### Git Workflow

```
1. Fork/Clone repository
2. Tạo branch mới: git checkout -b feature/ten-feature
3. Viết code và commit: git add . && git commit -m "message"
4. Push code: git push origin feature/ten-feature
5. Tạo Pull Request trên GitHub
6. Merge sau khi được review
```
Description:
Currently transactions only store basic information like amount and category.
This makes it difficult to understand the context of each expense.

Proposed Solution:
- Add a "note" field for each transaction
- Add "tags" (multiple tags per transaction)
- Allow filtering transactions by tag
- Add statistics by tag

Benefits:
- Improve user experience
- Better tracking and analysis of spending
- Create foundation for future AI features
### Quy tắc Commit

- `feat:` - Triển khai một tính năng hoàn toàn mới.
- `fix:` - Khắc phục các lỗi kỹ thuật hoặc lỗi logic.
- `docs:` - Chỉ thay đổi hoặc cập nhật tài liệu hướng dẫn.
- `style:` - Thay đổi liên quan đến định dạng code (khoảng trắng, dấu phẩy...) mà không làm thay đổi logic.
- `refactor:` - Tái cấu trúc mã nguồn để tối ưu hiệu suất hoặc độ sạch, không sửa lỗi hay thêm tính năng.

## 📝 Ghi chú phát triển

- Bảo vệ nhánh Main: Nhánh main được thiết lập chế độ bảo vệ nghiêm ngặt. Mọi thay đổi bắt buộc phải thông qua quy trình Pull Request (PR) và được kiểm duyệt (Review) bởi thành viên có thẩm quyền.
- Đảm bảo chất lượng: Tất cả các đoạn mã mới hoặc chỉnh sửa đều phải vượt qua các bài kiểm tra (Unit Test/Integration Test) trước khi thực hiện thao tác Merge.
- Cập nhật tài liệu: Ngay khi có những thay đổi lớn về logic hoặc cấu trúc dữ liệu, yêu cầu cập nhật tệp README.md để đảm bảo tính đồng bộ cho toàn đội ngũ.

## 📞 Liên hệ

**Team Lead**: Báo Ngọc Thiên Bảo  
**MSSV**: 1721031139

---

*Cập nhật lần cuối: 21/03/2026*
