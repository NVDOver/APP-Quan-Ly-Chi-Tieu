"use server";

import { addDays, endOfDay, format, startOfDay } from "date-fns";
import prisma from "@/lib/prisma";

const DEFAULT_PREFERENCES = {
  dailyInputEnabled: true,
  budgetAlertEnabled: true,
  recurringReminderEnabled: true,
  dailyReminderHour: 20,
  recurringReminderDays: 2,
} as const;

type NotificationCreateInput = {
  userId: string;
  type: "DAILY_INPUT_REMINDER" | "BUDGET_WARNING" | "BUDGET_EXCEEDED" | "RECURRING_DUE";
  title: string;
  message: string;
  link?: string;
  dedupeKey: string;
};

async function ensurePreference(userId: string) {
  return prisma.notificationPreference.upsert({
    where: { userId },
    update: {},
    create: {
      userId,
      ...DEFAULT_PREFERENCES,
    },
  });
}

async function createNotificationIfMissing(input: NotificationCreateInput) {
  const existing = await prisma.notification.findUnique({
    where: { dedupeKey: input.dedupeKey },
    select: { id: true },
  });

  if (existing) {
    return false;
  }

  await prisma.notification.create({
    data: input,
  });

  return true;
}

async function syncDailyInputReminder(userId: string, dailyReminderHour: number) {
  const now = new Date();
  if (now.getHours() < dailyReminderHour) {
    return 0;
  }

  const todayStart = startOfDay(now);
  const todayEnd = endOfDay(now);

  const hasTransactionToday = await prisma.transaction.findFirst({
    where: {
      userId,
      date: {
        gte: todayStart,
        lte: todayEnd,
      },
    },
    select: { id: true },
  });

  if (hasTransactionToday) {
    return 0;
  }

  const dedupeKey = `daily-input:${userId}:${format(todayStart, "yyyy-MM-dd")}`;
  const created = await createNotificationIfMissing({
    userId,
    type: "DAILY_INPUT_REMINDER",
    title: "Nhắc nhập liệu hôm nay",
    message: "Hôm nay bạn chưa ghi nhận giao dịch nào. Hãy cập nhật để theo dõi chi tiêu chính xác hơn.",
    link: "/transactions",
    dedupeKey,
  });

  return created ? 1 : 0;
}

async function syncBudgetNotifications(userId: string) {
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
  const monthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59, 999);

  const budgets = await prisma.budget.findMany({
    where: {
      userId,
      monthYear: monthStart,
    },
    include: {
      category: true,
    },
  });

  if (budgets.length === 0) {
    return 0;
  }

  const categoryIds = budgets
    .map((budget) => budget.categoryId)
    .filter((categoryId): categoryId is string => Boolean(categoryId));

  const spendingByCategory = categoryIds.length
    ? await prisma.transaction.groupBy({
        by: ["categoryId"],
        where: {
          userId,
          type: "EXPENSE",
          categoryId: { in: categoryIds },
          date: {
            gte: monthStart,
            lte: monthEnd,
          },
        },
        _sum: { amount: true },
      })
    : [];

  const spendingMap = new Map(
    spendingByCategory.map((entry) => [entry.categoryId, Number(entry._sum.amount || 0)])
  );

  let createdCount = 0;

  for (const budget of budgets) {
    const spentAmount = spendingMap.get(budget.categoryId ?? "") || 0;
    const limitAmount = Number(budget.limitAmount);
    if (limitAmount <= 0) {
      continue;
    }

    const progress = (spentAmount / limitAmount) * 100;
    const categoryName = budget.category?.name || "Ngân sách";
    const monthKey = format(monthStart, "yyyy-MM");

    if (progress >= 100) {
      const wasCreated = await createNotificationIfMissing({
        userId,
        type: "BUDGET_EXCEEDED",
        title: `Đã vượt ngân sách: ${categoryName}`,
        message: `Bạn đã chi ${Math.round(progress)}% ngân sách cho danh mục ${categoryName}. Hãy kiểm soát các khoản phát sinh tiếp theo.`,
        link: "/budgets",
        dedupeKey: `budget-exceeded:${budget.id}:${monthKey}`,
      });
      createdCount += wasCreated ? 1 : 0;
      continue;
    }

    if (progress >= 80) {
      const wasCreated = await createNotificationIfMissing({
        userId,
        type: "BUDGET_WARNING",
        title: `Sắp chạm ngưỡng ngân sách: ${categoryName}`,
        message: `Bạn đã sử dụng ${Math.round(progress)}% ngân sách của danh mục ${categoryName}.`,
        link: "/budgets",
        dedupeKey: `budget-warning:${budget.id}:${monthKey}`,
      });
      createdCount += wasCreated ? 1 : 0;
    }
  }

  return createdCount;
}

async function syncRecurringDueNotifications(userId: string, recurringReminderDays: number) {
  const now = new Date();
  const todayStart = startOfDay(now);
  const thresholdDate = endOfDay(addDays(todayStart, recurringReminderDays));

  const recurringItems = await prisma.recurringTransaction.findMany({
    where: {
      userId,
      status: "ACTIVE",
      nextProcessingDate: {
        gte: todayStart,
        lte: thresholdDate,
      },
    },
    include: {
      category: true,
    },
  });

  let createdCount = 0;

  for (const item of recurringItems) {
    const dueLabel = format(item.nextProcessingDate, "dd/MM/yyyy");
    const name = item.note || item.category?.name || "Khoản thanh toán định kỳ";

    const wasCreated = await createNotificationIfMissing({
      userId,
      type: "RECURRING_DUE",
      title: `Sắp đến hạn: ${name}`,
      message: `Giao dịch định kỳ "${name}" sẽ được xử lý vào ngày ${dueLabel}.`,
      link: "/recurring-transactions",
      dedupeKey: `recurring-due:${item.id}:${format(item.nextProcessingDate, "yyyy-MM-dd")}`,
    });
    createdCount += wasCreated ? 1 : 0;
  }

  return createdCount;
}

export async function syncNotificationsForUser(userId: string) {
  const preference = await ensurePreference(userId);

  let createdCount = 0;

  if (preference.dailyInputEnabled) {
    createdCount += await syncDailyInputReminder(userId, preference.dailyReminderHour);
  }

  if (preference.budgetAlertEnabled) {
    createdCount += await syncBudgetNotifications(userId);
  }

  if (preference.recurringReminderEnabled) {
    createdCount += await syncRecurringDueNotifications(userId, preference.recurringReminderDays);
  }

  return createdCount;
}

export async function syncNotificationsForAllUsers() {
  const users = await prisma.user.findMany({
    select: { id: true },
  });

  let createdCount = 0;
  for (const user of users) {
    createdCount += await syncNotificationsForUser(user.id);
  }

  return {
    processedUsers: users.length,
    createdCount,
  };
}
