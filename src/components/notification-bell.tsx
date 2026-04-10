"use client";

import { useEffect, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { formatDistanceToNow } from "date-fns";
import { vi } from "date-fns/locale";
import { Bell, CheckCheck, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import {
  getNotifications,
  markAllNotificationsAsRead,
  markNotificationAsRead,
  type NotificationItem,
} from "@/app/actions/notification-actions";

type NotificationState = {
  items: NotificationItem[];
  unreadCount: number;
};

export function NotificationBell() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [isPending, startTransition] = useTransition();
  const [data, setData] = useState<NotificationState>({
    items: [],
    unreadCount: 0,
  });
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
    let isSubscribed = true;

    const fetchNotifications = async () => {
      try {
        const result = await getNotifications();
        if (!isSubscribed) return;

        if (result.success && result.data) {
          setData(result.data);
        } else if (!result.success) {
          toast.error(result.error || "Không thể tải thông báo");
        }
      } catch (error) {
        console.error("Failed to fetch notifications:", error);
      } finally {
        if (isSubscribed) setIsLoading(false);
      }
    };

    void fetchNotifications();

    return () => {
      isSubscribed = false;
    };
  }, []);

  useEffect(() => {
    if (!open) return;

    let isSubscribed = true;

    const refetchNotifications = async () => {
      try {
        const result = await getNotifications();
        if (!isSubscribed) return;

        if (result.success && result.data) {
          setData(result.data);
        } else if (!result.success) {
          toast.error(result.error || "Không thể tải thông báo");
        }
      } catch (error) {
        console.error("Failed to refetch notifications:", error);
      }
    };

    void refetchNotifications();

    return () => {
      isSubscribed = false;
    };
  }, [open]);

  const handleMarkAllAsRead = () => {
    startTransition(async () => {
      const result = await markAllNotificationsAsRead();
      if (!result.success) {
        toast.error(result.error || "Không thể cập nhật thông báo");
        return;
      }

      setData((current) => ({
        unreadCount: 0,
        items: current.items.map((item) => ({
          ...item,
          isRead: true,
        })),
      }));
      router.refresh();
    });
  };

  const handleNotificationClick = (item: NotificationItem) => {
    startTransition(async () => {
      if (!item.isRead) {
        const result = await markNotificationAsRead(item.id);
        if (!result.success) {
          toast.error(result.error || "Không thể đánh dấu đã đọc");
          return;
        }

        setData((current) => ({
          unreadCount: Math.max(current.unreadCount - 1, 0),
          items: current.items.map((notification) =>
            notification.id === item.id
              ? { ...notification, isRead: true }
              : notification
          ),
        }));
      }

      setOpen(false);
      router.push(item.link || "/");
      router.refresh();
    });
  };

  if (!isMounted) {
    return (
      <Button variant="ghost" size="icon" className="relative">
        <Bell className="h-5 w-5" />
      </Button>
    );
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="relative h-9 w-9 rounded-full"
          aria-label="Thông báo"
        >
          <Bell className="h-5 w-5" />
          {data.unreadCount > 0 && (
            <span className="absolute -right-0.5 -top-0.5 flex h-5 min-w-5 items-center justify-center rounded-full bg-rose-500 px-1 text-[10px] font-bold text-white">
              {data.unreadCount > 9 ? "9+" : data.unreadCount}
            </span>
          )}
        </Button>
      </PopoverTrigger>

      <PopoverContent align="end" className="w-[360px] p-0">
        <div className="border-b px-4 py-3">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-semibold">Thông báo</p>
              <p className="text-xs text-muted-foreground">
                {data.unreadCount > 0
                  ? `Bạn có ${data.unreadCount} thông báo chưa đọc`
                  : "Bạn đã xem hết thông báo"}
              </p>
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 px-2 text-xs"
              disabled={isPending || data.unreadCount === 0}
              onClick={handleMarkAllAsRead}
            >
              {isPending ? (
                <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
              ) : (
                <CheckCheck className="mr-1 h-3.5 w-3.5" />
              )}
              Đọc tất cả
            </Button>
          </div>
        </div>

        <div className="max-h-[420px] overflow-y-auto">
          {isLoading ? (
            <div className="flex items-center justify-center px-4 py-10 text-sm text-muted-foreground">
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Đang tải thông báo...
            </div>
          ) : data.items.length === 0 ? (
            <div className="px-4 py-10 text-center text-sm text-muted-foreground">
              Chưa có thông báo nào.
            </div>
          ) : (
            data.items.map((item) => (
              <button
                key={item.id}
                type="button"
                className={`w-full border-b px-4 py-3 text-left transition-colors hover:bg-accent/40 ${
                  item.isRead ? "bg-background" : "bg-primary/5"
                }`}
                onClick={() => handleNotificationClick(item)}
              >
                <div className="flex items-start gap-3">
                  <span
                    className={`mt-1 h-2.5 w-2.5 rounded-full ${
                      item.isRead ? "bg-muted" : "bg-emerald-500"
                    }`}
                  />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-semibold leading-5">{item.title}</p>
                    <p className="mt-1 text-xs leading-5 text-muted-foreground">
                      {item.message}
                    </p>
                    <p className="mt-2 text-[11px] text-muted-foreground">
                      {formatDistanceToNow(new Date(item.createdAt), {
                        addSuffix: true,
                        locale: vi,
                      })}
                    </p>
                  </div>
                </div>
              </button>
            ))
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
}
