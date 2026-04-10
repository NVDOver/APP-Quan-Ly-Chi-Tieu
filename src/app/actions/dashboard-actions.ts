"use server";

import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { startOfDay, subDays } from "date-fns";

export async function getDashboardMoMStats() {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    const now = new Date();
    const startOfCurrentMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const startOfLastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const endOfLastMonth = new Date(now.getFullYear(), now.getMonth(), 0);

    const [currentExpense, lastExpense] = await Promise.all([
      prisma.transaction.aggregate({
        where: { userId, date: { gte: startOfCurrentMonth }, type: 'EXPENSE' },
        _sum: { amount: true },
      }),
      prisma.transaction.aggregate({
        where: { userId, date: { gte: startOfLastMonth, lte: endOfLastMonth }, type: 'EXPENSE' },
        _sum: { amount: true },
      }),
    ]);

    const currentExpTotal = Number(currentExpense._sum.amount || 0);
    const lastExpTotal = Number(lastExpense._sum.amount || 0);

    let expDiffPercent = 0;
    if (lastExpTotal > 0) {
      expDiffPercent = Math.round(((currentExpTotal - lastExpTotal) / lastExpTotal) * 100);
    }

    return {
      currentExpTotal,
      lastExpTotal,
      expDiffPercent,
    };
  } catch (error) {
    console.error("MoM Stats Error:", error);
    return { currentExpTotal: 0, lastExpTotal: 0, expDiffPercent: 0 };
  }
}

export async function getDashboardChartData() {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    const thirtyDaysAgo = startOfDay(subDays(new Date(), 30));

    const [spendingByCategory, dailyStatsRaw, allCategories] = await Promise.all([
      prisma.transaction.groupBy({
        by: ['categoryId'],
        where: { userId, type: 'EXPENSE', date: { gte: thirtyDaysAgo } },
        _sum: { amount: true },
      }),
      // 2. Dữ liệu Bar Chart
      prisma.$queryRaw<{ date_label: string; income: number; expense: number }[]>`
        SELECT 
          TO_CHAR(date, 'DD/MM') as date_label,
          SUM(CASE WHEN type = 'INCOME' THEN amount ELSE 0 END) as income,
          SUM(CASE WHEN type = 'EXPENSE' THEN amount ELSE 0 END) as expense
        FROM transactions
        WHERE user_id = ${userId} AND date >= ${thirtyDaysAgo}
        GROUP BY TO_CHAR(date, 'DD/MM'), date
        ORDER BY date ASC
      `,
      prisma.category.findMany({ 
        where: { userId, isDeleted: false },
        select: { id: true, name: true, color: true }
      })
    ]);

    const pieChartData = spendingByCategory.map(item => {
      const category = allCategories.find(c => c.id === item.categoryId);
      return {
        name: category?.name || "Khác",
        value: Number(item._sum.amount || 0),
        color: category?.color || "#94a3b8",
      };
    }).filter(item => item.value > 0);


    const barChartData = dailyStatsRaw.map(item => ({
      date: item.date_label,
      income: Number(item.income || 0),
      expense: Number(item.expense || 0),
    }));

    return { pieChartData, barChartData };
  } catch (error) {
    console.error("Chart Data Error:", error);
    return { pieChartData: [], barChartData: [] };
  }
}

// Giữ lại hàm cũ để tránh break code (nếu cần) nhưng khuyến khích dùng hàm mới
export async function getDashboardStats() {
  const [mom, charts] = await Promise.all([
    getDashboardMoMStats(),
    getDashboardChartData()
  ]);
  
  return {
    ...charts,
    momStats: mom
  };
}

