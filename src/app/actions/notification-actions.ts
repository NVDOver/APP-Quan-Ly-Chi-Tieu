"use server";

import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { actionError, actionSuccess, type ActionResult } from "@/lib/action-types";
import { revalidatePath } from "next/cache";
import { syncNotificationsForUser } from "@/lib/notification-service";

export type NotificationItem = {
  id: string;
  type: string;
  title: string;
  message: string;
  link: string | null;
  isRead: boolean;
  createdAt: Date;
};

export type NotificationListResult = {
  items: NotificationItem[];
  unreadCount: number;
};

async function getAuthenticatedUserId() {
  const session = await auth();
  if (!session?.user?.id) {
    throw new Error("Unauthorized");
  }

  return session.user.id;
}

export async function getNotifications(): Promise<ActionResult<NotificationListResult>> {
  try {
    const userId = await getAuthenticatedUserId();
    await syncNotificationsForUser(userId);

    const [items, unreadCount] = await Promise.all([
      prisma.notification.findMany({
        where: { userId },
        orderBy: { createdAt: "desc" },
        take: 20,
        select: {
          id: true,
          type: true,
          title: true,
          message: true,
          link: true,
          isRead: true,
          createdAt: true,
        },
      }),
      prisma.notification.count({
        where: {
          userId,
          isRead: false,
        },
      }),
    ]);

    return actionSuccess({ items, unreadCount });
  } catch (error) {
    return actionError(error);
  }
}

export async function markNotificationAsRead(notificationId: string): Promise<ActionResult> {
  try {
    const userId = await getAuthenticatedUserId();

    const notification = await prisma.notification.findFirst({
      where: {
        id: notificationId,
        userId,
      },
      select: { id: true },
    });

    if (!notification) {
      throw new Error("Không tìm thấy thông báo");
    }

    await prisma.notification.update({
      where: { id: notification.id },
      data: {
        isRead: true,
        readAt: new Date(),
      },
    });

    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}

export async function markAllNotificationsAsRead(): Promise<ActionResult> {
  try {
    const userId = await getAuthenticatedUserId();

    await prisma.notification.updateMany({
      where: {
        userId,
        isRead: false,
      },
      data: {
        isRead: true,
        readAt: new Date(),
      },
    });

    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}
