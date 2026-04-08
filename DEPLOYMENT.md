# Hướng dẫn Triển khai (Deployment Guide)

Tài liệu này cung cấp các bước chi tiết để triển khai ứng dụng Quản lý Chi tiêu lên môi trường Production (Vercel) và kết nối với cơ sở dữ liệu PostgreSQL từ xa.

## 1. Chuẩn bị Cơ sở dữ liệu (PostgreSQL)

Bạn có thể sử dụng các dịch vụ DB-as-a-Service phổ biến để kết nối từ xa:

- **Neon (Khuyên dùng)**: [neon.tech](https://neon.tech/) - DB Serverless cực nhanh.
- **Supabase**: [supabase.com](https://supabase.com/) - Mạnh mẽ và miễn phí khởi điểm tốt.

### Các bước lấy Connection String:
1. Tạo một dự án mới trên Neon hoặc Supabase.
2. Sao chép chuỗi kết nối (Connection String). Định dạng tiêu chuẩn:
   `postgresql://USER:PASSWORD@HOST:5432/DATABASE_NAME?sslmode=require`
3. Nếu sử dụng Prisma trên Vercel, hãy đảm bảo chọn đúng chế độ kết nối (Direct connection vs Connection pooling).

## 2. Cấu hình Biến môi trường (Vercel)

Khi tạo dự án mới trên Vercel, hãy thêm các biến sau vào mục **Settings > Environment Variables**:

| Biến | Giá trị / Gợi ý | Mục đích |
| :--- | :--- | :--- |
| `DATABASE_URL` | `postgresql://...` | Prisma kết nối DB |
| `AUTH_SECRET` | `openssl rand -base64 32` | Bảo mật Session người dùng (v5) |
| `AUTH_URL` | `https://your-domain.vercel.app` | URL chính của ứng dụng |
| `AUTH_TRUST_HOST` | `true` | Cần thiết cho NextAuth v5 trên Vercel |
| `GEMINI_API_KEY` | `Lấy từ Google AI Studio` | Kích hoạt tính năng Cố vấn AI |

## 3. Triển khai lên Vercel

1. Kết nối kho lưu trữ GitHub của bạn với Vercel.
2. **Build Settings**: Vercel sẽ tự động nhận diện Next.js.
3. **Install Command**: `npm install`.
4. **Build Command**: `npx prisma generate && next build`.
5. **Deploy**: Nhấn Deploy và chờ ứng dụng trực tuyến.

## 4. Lưu ý quan trọng
- Sau khi đổi DB ở môi trường Production, hãy chạy `npx prisma db push` hoặc `npx prisma migrate deploy` để đồng bộ cấu trúc bảng.
- Đảm bảo `GEMINI_API_KEY` được bảo mật, không bao giờ đẩy vào Git.
