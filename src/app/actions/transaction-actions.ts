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
  tagIds: z.array(z.string()).optional(),
  locationName: z.string().optional(),
  latitude: z.number().optional(),
  longitude: z.number().optional(),
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
      // 1. Cập nhật số dư ví cho giao dịch chính
      if (parsedData.type === "TRANSFER") {
        if (!parsedData.toWalletId) throw new Error("Phải chọn ví nhận khi chuyển tiền");
        if (parsedData.walletId === parsedData.toWalletId) throw new Error("Ví nguồn và ví nhận phải khác nhau");

        await tx.wallet.update({
          where: { id: parsedData.walletId, userId },
          data: { balance: { decrement: parsedData.amount } },
        });

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

      // 2. Tạo bản ghi giao dịch chính
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const transaction = await (tx.transaction as any).create({
        data: {
          userId,
          walletId: parsedData.walletId,
          toWalletId: parsedData.toWalletId || null,
          categoryId: parsedData.categoryId || null,
          type: parsedData.type,
          amount: parsedData.amount,
          date: parsedData.date,
          note: parsedData.note,
          locationName: parsedData.locationName || null,
          latitude: parsedData.latitude || null,
          longitude: parsedData.longitude || null,
        },
      });

      // 3. Gắn tags nếu có
      if (parsedData.tagIds && parsedData.tagIds.length > 0) {
        await Promise.all(
          parsedData.tagIds.map((tagId) =>
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (tx as any).tagOnTransaction.create({
              data: { tagId, transactionId: transaction.id },
            })
          )
        );
      }

      // FEATURE: 5. Chế độ Tiết kiệm tự động (Round-up)
      // Nếu là chi tiêu (EXPENSE), tự động làm tròn đến 10.000đ gần nhất và bỏ vào Piggy Bank
      if (parsedData.type === "EXPENSE") {
        const roundUpAmount = (Math.ceil(parsedData.amount / 10000) * 10000) - parsedData.amount;
        
        if (roundUpAmount > 0) {
          // Tìm mục tiêu tiết kiệm đang bật Round-up (lấy cái gần nhất)
          const roundUpGoal = await tx.savingGoal.findFirst({
            // @ts-expect-error - isRoundUp is newly added feature not yet in Prisma schema types
            where: { userId, isRoundUp: true },
            orderBy: { createdAt: "desc" }
          });

          if (roundUpGoal) {
            // Trừ thêm tiền từ ví
            await tx.wallet.update({
              where: { id: parsedData.walletId, userId },
              data: { balance: { decrement: roundUpAmount } }
            });

            // Cộng vào mục tiêu tiết kiệm
            await tx.savingGoal.update({
              where: { id: roundUpGoal.id },
              data: { currentAmount: { increment: roundUpAmount } }
            });

            // Tạo bản ghi giao dịch Tiết kiệm tự động
            await tx.transaction.create({
              data: {
                userId,
                walletId: parsedData.walletId,
                savingGoalId: roundUpGoal.id,
                type: "EXPENSE",
                amount: roundUpAmount,
                date: parsedData.date,
                note: `Tiết kiệm tự động (Round-up) từ giao dịch ${formatCurrency(parsedData.amount)}`
              }
            });
          }
        }
      }
      // FEATURE: 2. Hệ thống Nhắc nhở (Budget Alerts)
      if (parsedData.type === "EXPENSE" && parsedData.categoryId) {
        const today = new Date();
        const startOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);

        const budget = await tx.budget.findFirst({
          where: { userId, categoryId: parsedData.categoryId, monthYear: startOfMonth }
        });

        if (budget) {
          // Tính tổng chi tiêu hiện tại của category trong tháng
          const catExpenses = await tx.transaction.aggregate({
            where: { 
              userId, 
              categoryId: parsedData.categoryId, 
              type: "EXPENSE",
              date: { gte: startOfMonth }
            },
            _sum: { amount: true }
          });

          const totalUsed = Number(catExpenses._sum.amount || 0);
          const limit = Number(budget.limitAmount);
          const newUsagePercent = (totalUsed / limit) * 100;

          if (newUsagePercent >= 100) {
            // Đã vượt ngưỡng 100%
          } else if (newUsagePercent >= 80) {
            // Sắp chạm ngưỡng 80%
          }
        }
      }
    });

    // Helper nội bộ để format tiền trong note
    function formatCurrency(val: number) {
      return new Intl.NumberFormat("vi-VN").format(val) + "đ";
    }

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

  const [rawTransactions, total] = await Promise.all([
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (prisma.transaction as any).findMany({
      where,
      skip,
      take: pageSize,
      orderBy: { date: "desc" },
      include: {
        wallet: true,
        toWallet: true,
        category: true,
        tags: { include: { tag: true } },
      },
    }),
    prisma.transaction.count({ where }),
  ]);

  // Serialize Decimal → number để tránh lỗi khi truyền sang Client Components
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const transactions = (rawTransactions as any).map((t: any) => ({
    ...t,
    amount: Number(t.amount),
    wallet: t.wallet ? { ...t.wallet, balance: Number(t.wallet.balance) } : t.wallet,
    toWallet: t.toWallet ? { ...t.toWallet, balance: Number(t.toWallet.balance) } : t.toWallet,
  }));

  return {
    transactions,
    total,
    totalPages: Math.ceil(total / pageSize),
  };
}

export async function getFormOptions() {
  const session = await auth();
  if (!session?.user?.id) return { wallets: [], categories: [], tags: [] };

  const [rawWallets, categories, tags] = await Promise.all([
    prisma.wallet.findMany({ where: { userId: session.user.id } }),
    prisma.category.findMany({ where: { userId: session.user.id, isDeleted: false } }),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (prisma as any).tag.findMany({ where: { userId: session.user.id } })
  ]);

  // Serialize Decimal → number để tránh lỗi khi truyền sang Client Components
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const wallets = (rawWallets as any).map((w: any) => ({ ...w, balance: Number(w.balance) }));

  return { wallets, categories, tags };
}

export async function getTransactionLocations() {
  const session = await auth();
  if (!session?.user?.id) return { success: false, data: [] };
  const userId = session.user.id;

  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const transactions = await (prisma.transaction as any).findMany({
      where: {
        userId,
        latitude: { not: null },
        longitude: { not: null },
      },
      select: {
        id: true,
        amount: true,
        type: true,
        locationName: true,
        latitude: true,
        longitude: true,
        category: { select: { name: true } }
      },
      orderBy: { date: "desc" },
      take: 50,
    });

    return { success: true, data: transactions };
  } catch {
    return { success: false, data: [] };
  }
}
