"use server";

import { z } from "zod";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { revalidatePath } from "next/cache";
import type { Prisma, TransactionType } from "@prisma/client";

const createTransactionSchema = z.object({
  type: z.enum(["INCOME", "EXPENSE", "TRANSFER"]),
  walletId: z.string().min(1, "Vui lòng chọn ví"),
  toWalletId: z.string().optional(),
  categoryId: z.string().optional(),
  amount: z.number().positive("Số tiền phải lớn hơn 0"),
  date: z.date(),
  note: z.string().optional(),
});

export async function createTransaction(data: z.infer<typeof createTransactionSchema>) {
  try {
    const session = await auth();
    if (!session?.user?.id) {
      throw new Error("Unauthorized");
    }
    const userId = session.user.id;

    const parsedData = createTransactionSchema.parse(data);

    await prisma.$transaction(async (tx) => {
      // 1. Cập nhật số dư ví
      if (parsedData.type === "TRANSFER") {
        if (!parsedData.toWalletId) {
          throw new Error("Phải chọn ví nhận khi chuyển tiền");
        }
        if (parsedData.walletId === parsedData.toWalletId) {
          throw new Error("Ví nguồn và ví nhận phải khác nhau");
        }

        // Trừ ví nguồn
        await tx.wallet.update({
          where: { id: parsedData.walletId, userId },
          data: { balance: { decrement: parsedData.amount } },
        });

        // Cộng ví đích
        await tx.wallet.update({
          where: { id: parsedData.toWalletId, userId },
          data: { balance: { increment: parsedData.amount } },
        });
      } else {
        await tx.wallet.update({
          where: { id: parsedData.walletId, userId },
          data: {
            balance: parsedData.type === "INCOME"
              ? { increment: parsedData.amount }
              : { decrement: parsedData.amount },
          },
        });
      }

      // 2. Tạo bản ghi giao dịch duy nhất
      await tx.transaction.create({
        data: {
          userId,
          walletId: parsedData.walletId,
          toWalletId: parsedData.toWalletId || null,
          categoryId: parsedData.categoryId || null,
          type: parsedData.type,
          amount: parsedData.amount,
          date: parsedData.date,
          note: parsedData.note,
        },
      });
    });

    revalidatePath("/");
    revalidatePath("/transactions");
    return { success: true };
  } catch (error) {
    if (error instanceof z.ZodError) {
      return { success: false, error: error.issues[0].message };
    }
    if (error instanceof Error) {
      return { success: false, error: error.message };
    }
    return { success: false, error: "Đã xảy ra lỗi" };
  }
}

export async function deleteTransaction(transactionId: string) {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    await prisma.$transaction(async (tx) => {
      const transaction = await tx.transaction.findUnique({
        where: { id: transactionId, userId },
      });
      if (!transaction) throw new Error("Giao dịch không tồn tại");

      // Hoàn trả số dư ví
      if (transaction.type === "TRANSFER") {
        await tx.wallet.update({
          where: { id: transaction.walletId, userId },
          data: { balance: { increment: transaction.amount } },
        });
        if (transaction.toWalletId) {
          await tx.wallet.update({
            where: { id: transaction.toWalletId, userId },
            data: { balance: { decrement: transaction.amount } },
          });
        }
      } else {
        await tx.wallet.update({
          where: { id: transaction.walletId, userId },
          data: {
            balance:
              transaction.type === "INCOME"
                ? { decrement: transaction.amount }
                : { increment: transaction.amount },
          },
        });
      }

      // FIX: Nếu transaction này liên quan đến saving goal → hoàn trả
      if (transaction.savingGoalId) {
        await tx.savingGoal.update({
          where: { id: transaction.savingGoalId },
          data: { currentAmount: { decrement: transaction.amount } },
        });
      }

      await tx.transaction.delete({ where: { id: transactionId } });
    });

    revalidatePath("/");
    revalidatePath("/transactions");
    revalidatePath("/saving-goals"); // Thêm revalidate saving-goals
    return { success: true };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Đã xảy ra lỗi",
    };
  }
}

export async function getTransactions(params: {
  page?: number;
  pageSize?: number;
  type?: string;
  walletId?: string;
}) {
  const session = await auth();
  if (!session?.user?.id) throw new Error("Unauthorized");
  const userId = session.user.id;

  const { page = 1, pageSize = 10, type, walletId } = params;
  const skip = (page - 1) * pageSize;

  const where: Prisma.TransactionWhereInput = {
    userId
  };

  if (type && type !== "ALL") {
    where.type = type as TransactionType;
  }

  if (walletId && walletId !== "ALL") {
    where.OR = [
      { walletId: walletId },
      { toWalletId: walletId }
    ];
  }

  const [transactions, total] = await Promise.all([
    prisma.transaction.findMany({
      where,
      skip,
      take: pageSize,
      orderBy: { date: "desc" },
      include: {
        wallet: true,
        toWallet: true,
        category: true,
      },
    }),
    prisma.transaction.count({ where }),
  ]);

  return {
    transactions,
    total,
    totalPages: Math.ceil(total / pageSize),
  };
}

export async function getFormOptions() {
  const session = await auth();
  if (!session?.user?.id) return { wallets: [], categories: [] };

  const [wallets, categories] = await Promise.all([
    prisma.wallet.findMany({ where: { userId: session.user.id } }),
    prisma.category.findMany({ where: { userId: session.user.id, isDeleted: false } })
  ]);

  return { wallets, categories };
}
