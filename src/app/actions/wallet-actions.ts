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

    const transactionCount = await prisma.transaction.count({
      where: {
        userId,
        OR: [
          { walletId: id },
          { toWalletId: id },
        ],
      },
    });

    if (transactionCount > 0) {
      return {
        success: false,
        error: "Không thể xóa ví đã có giao dịch. Hãy xóa các giao dịch trước."
      };
    }

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
