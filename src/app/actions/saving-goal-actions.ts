"use server";

import { z } from "zod";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { revalidatePath } from "next/cache";
import { ActionResult, actionSuccess, actionError } from "@/lib/action-types";

const savingGoalSchema = z.object({
  name: z.string().min(1, "Tên mục tiêu không được để trống"),
  targetAmount: z.coerce.number().positive("Số tiền mục tiêu phải lớn hơn 0"),
  deadlineDate: z.string().or(z.date()),
  currentAmount: z.coerce.number().optional(),
  isRoundUp: z.boolean().optional(),
});

export async function createSavingGoal(data: z.infer<typeof savingGoalSchema>): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    const validatedData = savingGoalSchema.parse(data);

    await prisma.savingGoal.create({
      data: {
        ...validatedData,
        deadlineDate: new Date(validatedData.deadlineDate),
        userId,
        isRoundUp: !!validatedData.isRoundUp,
      },
    });

    revalidatePath("/saving-goals");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function updateSavingGoal(id: string, data: z.infer<typeof savingGoalSchema>): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    const validatedData = savingGoalSchema.parse(data);

    await prisma.savingGoal.update({
      where: { id, userId },
      data: {
        ...validatedData,
        deadlineDate: new Date(validatedData.deadlineDate),
        isRoundUp: !!validatedData.isRoundUp,
      },
    });

    revalidatePath("/saving-goals");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function deleteSavingGoal(id: string): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    await prisma.savingGoal.delete({
      where: { id, userId },
    });

    revalidatePath("/saving-goals");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function addContribution(
  goalId: string,
  walletId: string,
  amount: number,
  note?: string
): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    if (amount <= 0) return { success: false, error: "Số tiền nạp phải lớn hơn 0" };

    await prisma.$transaction(async (tx) => {
      const goal = await tx.savingGoal.findUnique({
        where: { id: goalId, userId },
      });
      if (!goal) throw new Error("Không tìm thấy mục tiêu tiết kiệm");

      const wallet = await tx.wallet.findUnique({
        where: { id: walletId, userId },
      });
      if (!wallet) throw new Error("Không tìm thấy ví");
      
      if (Number(wallet.balance) < amount) {
        throw new Error("Số dư ví không đủ để nạp vào mục tiêu");
      }

      await tx.wallet.update({
        where: { id: walletId },
        data: { balance: { decrement: amount } },
      });

      await tx.savingGoal.update({
        where: { id: goalId },
        data: { currentAmount: { increment: amount } },
      });

      await tx.transaction.create({
        data: {
          userId,
          walletId,
          savingGoalId: goalId,
          amount,
          type: "EXPENSE",
          date: new Date(),
          note: note || `Nạp tiền vào mục tiêu: ${goal.name}`,
        },
      });
    });

    revalidatePath("/saving-goals");
    revalidatePath("/wallets");
    revalidatePath("/transactions");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function getSavingGoals() {
  const session = await auth();
  if (!session?.user?.id) return [];
  const userId = session.user.id;

  const goals = await prisma.savingGoal.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
  });

  // Serialize Decimal → number để tránh lỗi khi truyền sang Client Components
  return goals.map((g) => ({
    ...g,
    targetAmount: Number(g.targetAmount),
    currentAmount: Number(g.currentAmount),
  }));
}
