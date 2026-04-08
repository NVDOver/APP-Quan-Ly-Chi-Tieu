"use server";

import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { revalidatePath } from "next/cache";
import { ActionResult, actionSuccess, actionError } from "@/lib/action-types";
import { z } from "zod";

const profileSchema = z.object({
  fullName: z.string().min(2, "Họ tên phải có ít nhất 2 ký tự"),
  email: z.string().email("Email không hợp lệ").optional(),
  preferredCurrency: z.string().optional(),
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

    // Cập nhật currency trong metadata hoặc bảng User nếu có
    // Giả sử ta thêm field này vào User sau
    
    revalidatePath("/profile");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}