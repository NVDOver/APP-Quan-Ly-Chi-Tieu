# 🚀 Hướng dẫn Triển khai Toàn cầu (Deployment Guide)

Tài liệu này hướng dẫn bạn đưa ứng dụng **Quản lý Chi tiêu** từ máy tính cá nhân lên internet để bất kỳ ai cũng có thể truy cập mọi lúc, mọi nơi.

---

## 📋 Điều kiện cần (Prerequisites)

Trước khi bắt đầu, hãy đảm bảo bạn đã đăng ký tài khoản tại các dịch vụ miễn phí sau:
1.  **[GitHub](https://github.com/)**: Lưu trữ mã nguồn (Source Code).
2.  **[Neon.tech](https://neon.tech/)**: Lưu trữ Cơ sở dữ liệu (PostgreSQL) đám mây.
3.  **[Vercel](https://vercel.com/)**: Máy chủ lưu trữ ứng dụng Web.

---

## 🛠 Giai đoạn 1: Đưa mã nguồn lên GitHub

Để Vercel có thể lấy mã nguồn của bạn, bạn cần đẩy dự án lên GitHub.

1.  Tạo một **New Repository** trên GitHub (đặt tên ví dụ: `app-quan-ly-chi-tieu`).
2.  Mở terminal tại thư mục gốc của dự án và chạy các lệnh:
    ```bash
    git init
    git add .
    git commit -m "Initial commit"
    git branch -M main
    git remote add origin https://github.com/TEN_CUA_BAN/TEN_REPO.git
    git push -u origin main
    ```

---

## 💾 Giai đoạn 2: Thiết lập Cơ sở dữ liệu (Neon)

Vì cơ sở dữ liệu trên máy bạn (`localhost`) không thể truy cập từ internet, chúng ta cần một database "nằm trên mây".

1.  Đăng nhập vào [Neon.tech](https://neon.tech/).
2.  Tạo project mới (đặt tên tùy ý).
3.  Ở mục **Dashboard**, bạn sẽ thấy chuỗi **Connection String**. Hãy sao chép nó. Nó có dạng:
    `postgresql://neondb_owner:PASSWORD@ep-xxx-xxx.aws.neon.tech/neondb?sslmode=require`
4.  **Lưu lại chuỗi này**, chúng ta sẽ dùng nó trong bước tiếp theo.

---

## 🚀 Giai đoạn 3: Triển khai lên Vercel

1.  Đăng nhập vào [Vercel](https://vercel.com/).
2.  Chọn **Add New > Project**.
3.  Tìm và **Import** repository bạn vừa đẩy lên GitHub.
4.  Tại phần **Environment Variables**, hãy thêm các biến sau:

| Biến (Key) | Giá trị (Value) | Gợi ý |
| :--- | :--- | :--- |
| `DATABASE_URL` | Chuỗi đã lấy từ Neon | Dùng để kết nối DB |
| `AUTH_SECRET` | Một chuỗi ngẫu nhiên | Có thể tạo bằng: `openssl rand -base64 32` |
| `AUTH_TRUST_HOST` | `true` | Cần cho NextAuth hoạt động trên Vercel |
| `GEMINI_API_KEY` | Key của bạn | Lấy từ [Google AI Studio](https://aistudio.google.com/) |

5.  Nhấn **Deploy**. Vercel sẽ mất khoảng 1-2 phút để "nấu" ứng dụng của bạn.

---

## 🔄 Giai đoạn 4: Đồng bộ hóa Database

Sau khi Vercel báo "Deployment Successful", bạn cần đẩy cấu trúc bảng từ mã nguồn lên database mới trên Neon.

Mở terminal tại dự án local của bạn và chạy:
```bash
# Đổi DATABASE_URL trong file .env của bạn thành chuỗi Neon trước khi chạy lệnh này
npx prisma db push
```

---

## 🌟 Chúc mừng!
Ứng dụng của bạn hiện đã có thể truy cập qua URL dạng `ten-du-an.vercel.app`. Hãy gửi link này cho bạn bè để họ cùng trải nghiệm nhé!

### ⚠️ Lưu ý bảo mật
- KHÔNG bao giờ chia sẻ file `.env` hoặc các API Key lên GitHub.
- Vercel sẽ tự động cập nhật web mỗi khi bạn `git push` mã mới lên nhánh `main`.

