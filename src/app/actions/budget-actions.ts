"use server";

import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { startOfMonth, endOfMonth } from "date-fns";
import { revalidatePath } from "next/cache";
import { z } from "zod";
import { ActionResult, actionSuccess, actionError } from "@/lib/action-types";

const budgetSchema = z.object({
  categoryId: z.string().min(1, "Danh mục không được để trống"),
  limitAmount: z.number().min(1000, "Hạn mức tối thiểu là 1,000đ"),
  monthYear: z.date(),
});

export async function upsertBudget(
  data: z.infer<typeof budgetSchema>
): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    const validated = budgetSchema.parse(data);
    const normalizedMonth = startOfMonth(validated.monthYear);

    await prisma.budget.upsert({
      where: {
        userId_categoryId_monthYear: {
          userId,
          categoryId: validated.categoryId,
          monthYear: normalizedMonth,
        },
      },
      update: { limitAmount: validated.limitAmount },
      create: {
        userId,
        categoryId: validated.categoryId,
        limitAmount: validated.limitAmount,
        monthYear: normalizedMonth,
      },
    });

    revalidatePath("/budgets");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function deleteBudget(budgetId: string): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };

    const budget = await prisma.budget.findUnique({ where: { id: budgetId } });
    if (!budget || budget.userId !== session.user.id) {
       return { success: false, error: "Không tìm thấy ngân sách" };
    }

    await prisma.budget.delete({ where: { id: budgetId } });

    revalidatePath("/budgets");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function getBudgetsWithProgress() {
  const session = await auth();
  if (!session?.user?.id) throw new Error("Unauthorized");
  const userId = session.user.id;

  const now = new Date();
  const start = startOfMonth(now);
  const end = endOfMonth(now);

  // 1. Fetch budgets for the current month
  const budgets = await prisma.budget.findMany({
    where: {
      userId,
      monthYear: start,
    },
    include: {
      category: true,
    },
  });

  if (budgets.length === 0) return [];

  // 2. Fetch all relevant transactions in one query using groupBy
  const categoryIds = budgets
    .map((b) => b.categoryId)
    .filter((id): id is string => id !== null);

  const spendingData = await prisma.transaction.groupBy({
    by: ["categoryId"],
    where: {
      userId,
      categoryId: { in: categoryIds },
      type: "EXPENSE",
      date: { gte: start, lte: end },
    },
    _sum: {
      amount: true,
    },
  });

  // 3. Map spending data for fast lookup
  const spendingMap = new Map(
    spendingData.map((s) => [s.categoryId, Number(s._sum.amount || 0)])
  );

  // 4. Calculate progress for each budget
  const budgetWithProgress = budgets.map((budget) => {
    const spentAmount = spendingMap.get(budget.categoryId!) || 0;
    const limitAmount = Number(budget.limitAmount);
    const remainingAmount = limitAmount - spentAmount;
    const progress = limitAmount > 0 ? (spentAmount / limitAmount) * 100 : 0;

    return {
      ...budget,
      spentAmount,
      limitAmount,
      remainingAmount,
      progress: Math.min(progress, 100), // Cap for visual progress bar
      actualProgress: progress, // Real percentage (can exceed 100%)
    };
  });

  return budgetWithProgress;
}
