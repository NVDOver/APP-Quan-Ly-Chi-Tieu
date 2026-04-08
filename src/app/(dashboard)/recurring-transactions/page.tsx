import { getRecurringTransactions } from "@/app/actions/recurring-actions";
import { getFormOptions } from "@/app/actions/transaction-actions";
import { RecurringList } from "@/components/recurring-transactions/recurring-list";
import { RecurringForm } from "@/components/recurring-transactions/recurring-form";
import { Repeat } from "lucide-react";

export const metadata = {
  title: "Giao dịch định kỳ | Quản lý Chi tiêu",
};

export default async function RecurringTransactionsPage() {
  const [recurringData, options] = await Promise.all([
    getRecurringTransactions(),
    getFormOptions(),
  ]);

  return (
    <div className="flex-1 space-y-4 p-4 md:p-8 pt-6">
      <div className="flex items-center justify-between space-y-2">
        <h2 className="text-3xl font-bold tracking-tight flex items-center gap-2">
          <Repeat className="w-8 h-8 text-primary" />
          Giao dịch định kỳ
        </h2>
        <div className="flex items-center space-x-2">
          <RecurringForm wallets={options.wallets} categories={options.categories} />
        </div>
      </div>

      <div className="mt-8">
         <p className="text-muted-foreground mb-4">
            Thiết lập các khoản thu/chi tự động lặp lại theo chu kỳ (Lương, tiện ích, hóa đơn mạng, trả góp...). 
            Hệ thống sẽ tự động cập nhật số dư ví và ghi nhận lịch sử vào đúng ngày định kỳ.
         </p>
         <RecurringList data={recurringData} />
      </div>
    </div>
  );
}
