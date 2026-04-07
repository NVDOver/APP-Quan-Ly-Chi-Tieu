"use server";

import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import * as XLSX from "xlsx";
import { ActionResult, actionSuccess, actionError } from "@/lib/action-types";

export type TrendData = {
  key: string;
  label: string;
  income: number;
  expense: number;
};

export async function exportTransactionsToExcel(): Promise<ActionResult<string>> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    const transactions = await prisma.transaction.findMany({
      where: { userId },
      include: {
        wallet: true,
        toWallet: true,
        category: true,
      },
      orderBy: { date: "desc" },
    });

    const data = transactions.map((t) => ({
      "Ngày": new Date(t.date).toLocaleDateString("vi-VN"),
      "Loại": t.type === "INCOME" ? "Thu nhập" : t.type === "EXPENSE" ? "Chi tiêu" : "Chuyển tiền",
      "Danh mục": t.category?.name || (t.type === "TRANSFER" ? "Chuyển khoản" : "N/A"),
      "Ví/Nguồn": t.wallet.name,
      "Đến ví": t.toWallet?.name || "",
      "Số tiền": Number(t.amount),
      "Ghi chú": t.note || "",
    }));

    const worksheet = XLSX.utils.json_to_sheet(data);
    const wscols = [
      { wch: 15 }, { wch: 15 }, { wch: 20 }, { wch: 20 }, { wch: 20 }, { wch: 15 }, { wch: 30 },
    ];
    worksheet["!cols"] = wscols;

    const workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, worksheet, "Giao dịch");

    const buffer = XLSX.write(workbook, { type: "base64", bookType: "xlsx" });

    return actionSuccess(buffer);
  } catch (error) {
    return actionError(error);
  }
}

export async function getCashFlowTrend(): Promise<ActionResult<TrendData[]>> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    const months = Array.from({ length: 6 }).map((_, i) => {
      const d = new Date();
      d.setDate(1);
      d.setMonth(d.getMonth() - (5 - i));
      d.setHours(0, 0, 0, 0);
      return {
        start: new Date(d),
        end: new Date(d.getFullYear(), d.getMonth() + 1, 0, 23, 59, 59, 999),
        key: `${d.getFullYear()}-${(d.getMonth() + 1).toString().padStart(2, "0")}`,
        label: `Tháng ${d.getMonth() + 1}/${d.getFullYear()}`,
        income: 0,
        expense: 0,
      };
    });

    const sixMonthsAgo = months[0].start;

    const result = await prisma.$queryRaw<
      Array<{ month_key: string; type: string; total: number }>
    >`
      SELECT
        TO_CHAR(date, 'YYYY-MM') AS month_key,
        type,
        SUM(amount)::float AS total
      FROM transactions
      WHERE
        user_id = ${userId}
        AND date >= ${sixMonthsAgo}
        AND type IN ('INCOME', 'EXPENSE')
      GROUP BY month_key, type
      ORDER BY month_key ASC
    `;

    result.forEach((row) => {
      const month = months.find((m) => m.key === row.month_key);
      if (month) {
        if (row.type === "INCOME") month.income = Number(row.total);
        if (row.type === "EXPENSE") month.expense = Number(row.total);
      }
    });

    return actionSuccess(
      months.map(({ key, label, income, expense }) => ({
        key,
        label,
        income,
        expense,
      }))
    );
  } catch (error) {
    return actionError(error);
  }
}
