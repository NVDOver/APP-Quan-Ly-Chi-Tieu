"use server";

import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { revalidatePath } from "next/cache";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { ActionResult, actionSuccess, actionError } from "@/lib/action-types";

const profileSchema = z.object({
  fullName: z.string().min(2, "Họ tên phải có ít nhất 2 ký tự"),
  email: z.string().email("Email không hợp lệ"),
  avatarUrl: z.string().url().optional().or(z.literal("")),
  currency: z.string().min(1),
});

const passwordSchema = z.object({
  currentPassword: z.string().min(1, "Vui lòng nhập mật khẩu hiện tại"),
  newPassword: z.string().min(6, "Mật khẩu mới phải có ít nhất 6 ký tự"),
});

export async function updateProfile(data: z.infer<typeof profileSchema>): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    const validated = profileSchema.parse(data);

    // Nếu đổi email, kiểm tra xem email mới có bị dùng bởi user khác không
    if (validated.email !== session.user.email) {
      const existingUser = await prisma.user.findUnique({
        where: { email: validated.email },
      });
      if (existingUser && existingUser.id !== userId) {
        return { success: false, error: "Email này đã được sử dụng bởi tài khoản khác!" };
      }
    }

    await prisma.user.update({
      where: { id: userId },
      data: {
        fullName: validated.fullName,
        email: validated.email,
        avatarUrl: validated.avatarUrl || null,
        currency: validated.currency,
      },
    });

    revalidatePath("/profile");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function updatePassword(data: z.infer<typeof passwordSchema>): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.email) return { success: false, error: "Unauthorized" };
    const email = session.user.email;

    const validated = passwordSchema.parse(data);

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) throw new Error("User not found");

    const isValid = await bcrypt.compare(validated.currentPassword, user.passwordHash);
    if (!isValid) {
      return { success: false, error: "Mật khẩu hiện tại không đúng." };
    }

    const hashedPassword = await bcrypt.hash(validated.newPassword, 10);
    await prisma.user.update({
      where: { email },
      data: { passwordHash: hashedPassword },
    });

    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}