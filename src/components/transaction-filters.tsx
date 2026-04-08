"use client";

import { useRouter, useSearchParams } from "next/navigation";

interface WalletOption {
  id: string;
  name: string;
}

const selectClass =
  "flex h-9 w-full rounded-lg border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring";

export function TransactionFilters({ 
  wallets, 
  currentType, 
  currentWalletId 
}: { 
  wallets: WalletOption[], 
  currentType: string, 
  currentWalletId: string 
}) {
  const router = useRouter();
  const searchParams = useSearchParams();

  const updateFilters = (key: string, value: string) => {
    const params = new URLSearchParams(searchParams.toString());
    params.set(key, value);
    params.set("page", "1");
    router.push(`/transactions?${params.toString()}`);
  };

  return (
    <div className="flex flex-wrap gap-4">
      <div className="min-w-[150px] space-y-1.5">
        <label className="text-xs font-medium text-muted-foreground uppercase">Loại giao dịch</label>
        <select
          className={selectClass}
          value={currentType || "ALL"}
          onChange={(e) => updateFilters("type", e.target.value)}
        >
          <option value="ALL">Tất cả loại</option>
          <option value="INCOME">Thu nhập</option>
          <option value="EXPENSE">Chi tiêu</option>
          <option value="TRANSFER">Chuyển khoản</option>
        </select>
      </div>

      <div className="min-w-[200px] space-y-1.5">
        <label className="text-xs font-medium text-muted-foreground uppercase">Ví tài khoản</label>
        <select
          className={selectClass}
          value={currentWalletId || "ALL"}
          onChange={(e) => updateFilters("walletId", e.target.value)}
        >
          <option value="ALL">Tất cả ví</option>
          {wallets.map((w) => (
            <option key={w.id} value={w.id}>
              {w.name}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}
