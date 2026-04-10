import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import bcrypt from "bcryptjs";
import { z } from "zod";

const registerSchema = z.object({
  fullName: z.string().min(1, "Họ và tên không được để trống"),
  email: z.string().email("Email không hợp lệ"),
  password: z.string().min(6, "Mật khẩu phải từ 6 ký tự trở lên"),
});

export async function POST(req: Request) {
  console.log("POST /api/auth/register - Request received");
  try {
    const body = await req.json();
    console.log("Request body:", { ...body, password: "[REDACTED]" });
    const { fullName, email, password } = registerSchema.parse(body);

    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return NextResponse.json(
        { message: "Email này đã được sử dụng." },
        { status: 409 }
      );
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Sử dụng $transaction để bọc toàn bộ khối cập nhật nhằm đảm bảo tính toàn vẹn (Integrity)
    const newUser = await prisma.$transaction(async (tx) => {
      // 1. Tạo User
      const user = await tx.user.create({
        data: {
          email,
          fullName,
          passwordHash: hashedPassword,
        },
      });

      // 2. Tạo Wallet mặc định ("Tiền mặt")
      await tx.wallet.create({
        data: {
          userId: user.id,
          name: "Tiền mặt",
          balance: 0,
        },
      });

      await tx.notificationPreference.create({
        data: {
          userId: user.id,
        },
      });

      // 3. Tạo 5 Category mặc định (1 INCOME, 4 EXPENSE)
      const categories = [
        { name: "Lương", type: "INCOME" as const },
        { name: "Ăn uống", type: "EXPENSE" as const },
        { name: "Di chuyển", type: "EXPENSE" as const },
        { name: "Hóa đơn", type: "EXPENSE" as const },
        { name: "Giải trí", type: "EXPENSE" as const },
      ];

      await tx.category.createMany({
        data: categories.map((cat) => ({
          userId: user.id,
          name: cat.name,
          type: cat.type,
        })),
      });

      return user;
    });

    return NextResponse.json(
      { message: "Tạo tài khoản thành công!", userId: newUser.id },
      { status: 201 }
    );
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ message: error.issues[0].message }, { status: 400 });
    }
    console.error("Lỗi đăng ký:", error);
    return NextResponse.json(
      { message: "Đã có lỗi xảy ra từ máy chủ." },
      { status: 500 }
    );
  }
}
