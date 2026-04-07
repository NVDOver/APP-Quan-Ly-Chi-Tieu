"use server";

import { z } from "zod";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { revalidatePath } from "next/cache";
import { ActionResult, actionSuccess, actionError } from "@/lib/action-types";

const categorySchema = z.object({
  name: z.string().min(1, "Tên danh mục không được để trống"),
  type: z.enum(["INCOME", "EXPENSE"]),
  icon: z.string().optional(),
  color: z.string().optional(),
});

export async function createCategory(data: z.infer<typeof categorySchema>): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    const validatedData = categorySchema.parse(data);

    await prisma.category.create({
      data: {
        ...validatedData,
        userId,
      },
    });

    revalidatePath("/categories");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function updateCategory(id: string, data: z.infer<typeof categorySchema>): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    const validatedData = categorySchema.parse(data);

    await prisma.category.update({
      where: { id, userId },
      data: validatedData,
    });

    revalidatePath("/categories");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function deleteCategory(id: string): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    // Áp dụng cơ chế Soft Delete (is_deleted) như thiết kế trong Schema
    await prisma.category.update({
      where: { id, userId },
      data: { isDeleted: true },
    });

    revalidatePath("/categories");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function getCategories() {
  const session = await auth();
  if (!session?.user?.id) throw new Error("Unauthorized");
  return prisma.category.findMany({
    where: { 
      userId: session.user.id,
      isDeleted: false 
    },
    orderBy: { name: "asc" }
  });
}
