"use server";

import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { startOfDay, subDays, format } from "date-fns";

export async function getDashboardStats() {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    const thirtyDaysAgo = startOfDay(subDays(new Date(), 30));

    // 1. Dữ liệu Pie Chart: Tổng chi tiêu theo Danh mục
    const spendingByCategory = await prisma.transaction.groupBy({
      by: ['categoryId'],
      where: {
        userId,
        type: 'EXPENSE',
        date: { gte: thirtyDaysAgo },
      },
      _sum: {
        amount: true,
      },
    });

    const catIds = spendingByCategory.map(s => s.categoryId).filter((id): id is string => id !== null);
    const categories = await prisma.category.findMany({
      where: { id: { in: catIds } }
    });

    const pieChartData = spendingByCategory.map(item => {
      const category = categories.find(c => c.id === item.categoryId);
      return {
        name: category?.name || "Khác",
        value: Number(item._sum.amount || 0),
        color: category?.color || "#94a3b8",
      };
    }).filter(item => item.value > 0);

    // 2. Dữ liệu Bar/Line Chart: Thu nhập vs Chi tiêu theo ngày (Tối ưu SQL - Mục 4.1)
    // Dùng đúng mapping @@map từ schema.prisma
    const dailyStatsRaw = await prisma.$queryRaw<any[]>`
      SELECT 
        TO_CHAR(date, 'DD/MM') as date_label,
        SUM(CASE WHEN type = 'INCOME' THEN amount ELSE 0 END) as income,
        SUM(CASE WHEN type = 'EXPENSE' THEN amount ELSE 0 END) as expense
      FROM transactions
      WHERE user_id = ${userId} 
        AND date >= ${thirtyDaysAgo}
      GROUP BY TO_CHAR(date, 'DD/MM'), date
      ORDER BY date ASC
    `;

    const barChartData = dailyStatsRaw.map(item => ({
      date: item.date_label,
      income: Number(item.income || 0),
      expense: Number(item.expense || 0),
    }));

    // 3. So sánh tháng này vs tháng trước (MoM)
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
      pieChartData,
      barChartData,
      momStats: {
        currentExpTotal,
        lastExpTotal,
        expDiffPercent,
      }
    };
  } catch (error) {
    console.error("Dashboard Stats Error:", error);
    return {
      pieChartData: [],
      barChartData: [],
      momStats: { currentExpTotal: 0, lastExpTotal: 0, expDiffPercent: 0 }
    };
  }
}
