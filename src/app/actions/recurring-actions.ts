"use server";

import { z } from "zod";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { revalidatePath } from "next/cache";
import { ActionResult, actionSuccess, actionError } from "@/lib/action-types";

const recurringSchema = z.object({
  type: z.enum(["INCOME", "EXPENSE", "TRANSFER"]),
  interval: z.enum(["DAILY", "WEEKLY", "MONTHLY", "YEARLY"]),
  walletId: z.string().min(1, "Vui lòng chọn ví"),
  toWalletId: z.string().optional().nullable(),
  categoryId: z.string().optional().nullable(),
  amount: z.number().positive("Số tiền phải lớn hơn 0"),
  note: z.string().optional().nullable(),
  startDate: z.date(),
  endDate: z.date().optional().nullable(),
});

export async function createRecurringTransaction(data: z.infer<typeof recurringSchema>): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    const parsedData = recurringSchema.parse(data);

    if (parsedData.type === "TRANSFER") {
      if (!parsedData.toWalletId) throw new Error("Phải chọn ví nhận khi chuyển tiền");
      if (parsedData.walletId === parsedData.toWalletId) throw new Error("Ví nguồn và ví nhận phải khác nhau");
    }

    await prisma.recurringTransaction.create({
      data: {
        userId,
        walletId: parsedData.walletId,
        toWalletId: parsedData.toWalletId || null,
        categoryId: parsedData.categoryId || null,
        type: parsedData.type,
        interval: parsedData.interval,
        amount: parsedData.amount,
        note: parsedData.note,
        startDate: parsedData.startDate,
        endDate: parsedData.endDate || null,
        nextProcessingDate: parsedData.startDate,
        status: "ACTIVE",
      },
    });

    revalidatePath("/recurring-transactions");
    return actionSuccess();
  } catch (error) {
    if (error instanceof z.ZodError) return actionError(new Error(error.issues[0].message));
    return actionError(error);
  }
}

export async function updateRecurringTransaction(id: string, data: z.infer<typeof recurringSchema>): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    const parsedData = recurringSchema.parse(data);

    if (parsedData.type === "TRANSFER") {
      if (!parsedData.toWalletId) throw new Error("Phải chọn ví nhận khi chuyển tiền");
      if (parsedData.walletId === parsedData.toWalletId) throw new Error("Ví nguồn và ví nhận phải khác nhau");
    }

    await prisma.recurringTransaction.update({
      where: { id, userId },
      data: {
        walletId: parsedData.walletId,
        toWalletId: parsedData.toWalletId || null,
        categoryId: parsedData.categoryId || null,
        type: parsedData.type,
        interval: parsedData.interval,
        amount: parsedData.amount,
        note: parsedData.note,
        startDate: parsedData.startDate,
        endDate: parsedData.endDate || null,
        // Tuỳ chọn logic update nextProcessingDate nếu startDate thay đổi, nhưng để đơn giản ta update:
        nextProcessingDate: parsedData.startDate > new Date() ? parsedData.startDate : undefined
      },
    });

    revalidatePath("/recurring-transactions");
    return actionSuccess();
  } catch (error) {
    if (error instanceof z.ZodError) return actionError(new Error(error.issues[0].message));
    return actionError(error);
  }
}

export async function pauseRecurringTransaction(id: string): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");

    await prisma.recurringTransaction.update({
      where: { id, userId: session.user.id },
      data: { status: "PAUSED" },
    });

    revalidatePath("/recurring-transactions");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function resumeRecurringTransaction(id: string): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");

    await prisma.recurringTransaction.update({
      where: { id, userId: session.user.id },
      data: { status: "ACTIVE" },
    });

    revalidatePath("/recurring-transactions");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function deleteRecurringTransaction(id: string): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");

    await prisma.recurringTransaction.delete({
      where: { id, userId: session.user.id },
    });

    revalidatePath("/recurring-transactions");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function getRecurringTransactions() {
  const session = await auth();
  if (!session?.user?.id) throw new Error("Unauthorized");
  
  const transactions = await prisma.recurringTransaction.findMany({
    where: { userId: session.user.id },
    orderBy: { createdAt: "desc" },
    include: {
      wallet: true,
      toWallet: true,
      category: true,
    },
  });

  // Convert Decimal to number for Client Component serialization
  return transactions.map(tx => ({
    id: tx.id,
    userId: tx.userId,
    walletId: tx.walletId,
    toWalletId: tx.toWalletId,
    categoryId: tx.categoryId,
    amount: Number(tx.amount),
    type: tx.type,
    note: tx.note,
    interval: tx.interval,
    status: tx.status,
    startDate: tx.startDate,
    endDate: tx.endDate,
    nextProcessingDate: tx.nextProcessingDate,
    lastProcessedDate: tx.lastProcessedDate,
    createdAt: tx.createdAt,
    updatedAt: tx.updatedAt,
      wallet: tx.wallet ? {
      ...tx.wallet,
      balance: Number(tx.wallet.balance)
    } : null,
    toWallet: tx.toWallet ? {
      ...tx.toWallet,
      balance: Number(tx.toWallet.balance)
    } : null,
    category: tx.category,
  }));
}

interface CronResult {
  processedCount: number;
  errorsCount: number;
}

export async function triggerCronManually(): Promise<ActionResult<CronResult>> {
  try {
    const res = await fetch("http://localhost:3000/api/cron/process-recurring", {
      headers: {
        Authorization: `Bearer ${process.env.CRON_SECRET || 'dev_secret'}`
      }
    });
    
    if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Cron failed: ${errText}`);
    }
    const data = await res.json();
    return actionSuccess(data as CronResult);
  } catch (error) {
     return actionError(error);
  }
}
