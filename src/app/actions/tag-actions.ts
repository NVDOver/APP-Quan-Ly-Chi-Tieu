"use server";

import { z } from "zod";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { revalidatePath } from "next/cache";

const createTagSchema = z.object({
  name: z.string().min(1, "Tên tag không được để trống").max(50),
  color: z.string().optional(),
});

const TAG_COLORS = [
  "#ef4444", "#f97316", "#f59e0b", "#84cc16",
  "#22c55e", "#14b8a6", "#06b6d4", "#3b82f6",
  "#6366f1", "#8b5cf6", "#a855f7", "#ec4899",
];

export async function createTag(data: z.infer<typeof createTagSchema>) {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    const parsed = createTagSchema.parse(data);
    const tagName = parsed.name.toLowerCase().replace(/\s+/g, "-").replace(/^#/, "");

    // Auto-assign color if not provided
    const existingCount = await prisma.tag.count({ where: { userId } });
    const autoColor = parsed.color || TAG_COLORS[existingCount % TAG_COLORS.length];

    const tag = await prisma.tag.create({
      data: {
        userId,
        name: tagName,
        color: autoColor,
      },
    });

    revalidatePath("/tags");
    revalidatePath("/transactions");
    return { success: true, data: tag };
  } catch (error) {
    if (error instanceof Error && error.message.includes("Unique constraint")) {
      return { success: false, error: "Tag này đã tồn tại" };
    }
    return {
      success: false,
      error: error instanceof Error ? error.message : "Đã xảy ra lỗi",
    };
  }
}

export async function getTags() {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    const tags = await prisma.tag.findMany({
      where: { userId },
      orderBy: { name: "asc" },
      include: {
        _count: { select: { transactions: true } },
      },
    });

    return { success: true, data: tags };
  } catch {
    return { success: false, data: [] };
  }
}

export async function deleteTag(tagId: string) {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    await prisma.tag.delete({
      where: { id: tagId, userId },
    });

    revalidatePath("/tags");
    revalidatePath("/transactions");
    return { success: true };
  } catch {
    return { success: false, error: "Lỗi khi xoá tag" };
  }
}

export async function updateTag(tagId: string, data: { name?: string; color?: string }) {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    const tag = await prisma.tag.update({
      where: { id: tagId, userId },
      data: {
        ...(data.name && { name: data.name.toLowerCase().replace(/\s+/g, "-").replace(/^#/, "") }),
        ...(data.color && { color: data.color }),
      },
    });

    revalidatePath("/tags");
    return { success: true, data: tag };
  } catch {
    return { success: false, error: "Lỗi khi cập nhật tag" };
  }
}

export async function attachTagsToTransaction(transactionId: string, tagIds: string[]) {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");

    // Remove existing tags first, then add new ones (full replace)
    await prisma.$transaction([
      prisma.tagOnTransaction.deleteMany({ where: { transactionId } }),
      ...tagIds.map((tagId) =>
        prisma.tagOnTransaction.create({
          data: { tagId, transactionId },
        })
      ),
    ]);

    revalidatePath("/transactions");
    return { success: true };
  } catch {
    return { success: false, error: "Lỗi khi gắn tag" };
  }
}

export async function getTransactionsByTag(tagId: string) {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    const transactions = await prisma.transaction.findMany({
      where: {
        userId,
        tags: { some: { tagId } },
      },
      include: {
        wallet: true,
        category: true,
        tags: { include: { tag: true } },
      },
      orderBy: { date: "desc" },
    });

    return { success: true, data: transactions };
  } catch {
    return { success: false, data: [] };
  }
}
