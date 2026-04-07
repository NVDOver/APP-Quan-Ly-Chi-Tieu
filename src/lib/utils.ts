import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Format số tiền theo locale Việt Nam.
 * @param amount - Số tiền cần format
 * @param currency - Mã tiền tệ (mặc định: VND)
 */
export function formatCurrency(amount: number, currency = "VND"): string {
  return new Intl.NumberFormat("vi-VN", {
    style: "currency",
    currency,
    minimumFractionDigits: currency === "VND" ? 0 : 2,
    maximumFractionDigits: currency === "VND" ? 0 : 2,
  }).format(amount);
}

/**
 * Format số tiền ngắn gọn cho biểu đồ (ví dụ: 1,500,000 → 1.5M)
 */
export function formatCurrencyCompact(amount: number): string {
  if (amount >= 1_000_000) {
    return `${(amount / 1_000_000).toFixed(1)}M`;
  }
  if (amount >= 1_000) {
    return `${(amount / 1_000).toFixed(0)}k`;
  }
  return amount.toString();
}