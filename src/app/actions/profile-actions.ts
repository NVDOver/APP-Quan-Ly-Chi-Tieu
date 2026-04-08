"use server";

import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { revalidatePath } from "next/cache";
import { ActionResult, actionSuccess, actionError } from "@/lib/action-types";
import { z } from "zod";
import bcrypt from "bcryptjs";

const profileSchema = z.object({
  fullName: z.string().min(2, "Họ tên phải có ít nhất 2 ký tự"),
  email: z.string().email("Email không hợp lệ").optional(),
  preferredCurrency: z.string().optional(),
});

const passwordChangeSchema = z.object({
  currentPassword: z.string().min(1, "Vui lòng nhập mật khẩu hiện tại"),
  newPassword: z.string().min(6, "Mật khẩu mới phải có ít nhất 6 ký tự"),
});

export async function updateProfile(data: z.infer<typeof profileSchema>): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    const validatedData = profileSchema.parse(data);

    await prisma.user.update({
      where: { id: userId },
      data: {
        fullName: validatedData.fullName,
        // email: validatedData.email, // Thường không cho đổi email trực tiếp nếu dùng AuthProvider
      },
    });

    revalidatePath("/profile");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function updatePassword(data: z.infer<typeof passwordChangeSchema>): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    const validatedData = passwordChangeSchema.parse(data);

    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) return { success: false, error: "Không tìm thấy người dùng" };

    const passwordsMatch = await bcrypt.compare(validatedData.currentPassword, user.passwordHash);
    if (!passwordsMatch) {
      return { success: false, error: "Mật khẩu hiện tại không chính xác" };
    }

    const hashedNewPassword = await bcrypt.hash(validatedData.newPassword, 10);

    await prisma.user.update({
      where: { id: userId },
      data: { passwordHash: hashedNewPassword },
    });

    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}