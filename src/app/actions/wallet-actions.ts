"use server";

import { z } from "zod";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { revalidatePath } from "next/cache";
import { ActionResult, actionSuccess, actionError } from "@/lib/action-types";

const walletSchema = z.object({
  name: z.string().min(1, "Tên ví không được để trống"),
  balance: z.coerce.number().default(0),
  icon: z.string().optional(),
});

export async function createWallet(data: z.infer<typeof walletSchema>): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    const validatedData = walletSchema.parse(data);

    await prisma.wallet.create({
      data: {
        ...validatedData,
        userId,
      },
    });

    revalidatePath("/wallets");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function updateWallet(id: string, data: z.infer<typeof walletSchema>): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    const validatedData = walletSchema.parse(data);

    await prisma.wallet.update({
      where: { id, userId },
      data: validatedData,
    });

    revalidatePath("/wallets");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function deleteWallet(id: string): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    // Không cần check transactionCount nữa vì Prisma đã có onDelete: Cascade
    // Xóa ví đồng nghĩa với việc xóa tất cả giao dịch liên quan

    await prisma.wallet.delete({
      where: { id, userId },
    });

    revalidatePath("/wallets");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function getWallets() {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    const wallets = await prisma.wallet.findMany({
      where: { userId },
      orderBy: { name: "asc" },
    });

    return { success: true, wallets };
  } catch (error) {
    return { success: false, error: "Không thể lấy danh sách ví" };
  }
}
