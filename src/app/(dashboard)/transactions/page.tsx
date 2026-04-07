import { getTransactions, getFormOptions } from "@/app/actions/transaction-actions";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";
import { ArrowLeftRight, Filter } from "lucide-react";
import { DeleteTransactionButton } from "@/components/delete-transaction-button";
import { TransactionFilters } from "@/components/transaction-filters";
import { PaginationNav } from "@/components/pagination-nav";
import { formatCurrency, formatCurrencyCompact } from "@/lib/utils";
import type { Transaction, Wallet, Category } from "@prisma/client";

// Type chính xác từ Prisma (thay vì any)
type TransactionWithRelations = Transaction & {
  wallet: Wallet;
  toWallet: Wallet | null;
  category: Category | null;
};

export default async function TransactionsPage(props: {
  searchParams: Promise<{
    page?: string;
    type?: string;
    walletId?: string;
  }>;
}) {
  const searchParams = await props.searchParams;
  const page = Number(searchParams.page) || 1;
  const type = searchParams.type || "ALL";
  const walletId = searchParams.walletId || "ALL";

  const { transactions, totalPages } = await getTransactions({
    page,
    pageSize: 10,
    type,
    walletId
  });

  const { wallets } = await getFormOptions();

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Quản lý giao dịch</h1>
          <p className="text-muted-foreground"> Xem và quản lý lịch sử thu chi của bạn. </p>
        </div>
      </div>

      <div className="rounded-xl border bg-card p-4 shadow-sm">
        <div className="mb-4 flex items-center gap-2 font-semibold">
          <Filter className="h-4 w-4" />
          Bộ lọc
        </div>
        <TransactionFilters wallets={wallets} currentType={type} currentWalletId={walletId} />
      </div>

      <div className="rounded-xl border bg-card shadow-sm overflow-hidden">
        <Table>
          <TableHeader className="bg-muted/50">
            <TableRow>
              <TableHead className="w-[120px]">Ngày</TableHead>
              <TableHead>Danh mục / Mô tả</TableHead>
              <TableHead>Ví</TableHead>
              <TableHead className="text-right">Số tiền</TableHead>
              <TableHead className="w-[80px]"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {transactions.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="h-24 text-center text-muted-foreground">
                  Không tìm thấy giao dịch nào.
                </TableCell>
              </TableRow>
            ) : (
              transactions.map((t: TransactionWithRelations) => (
                <TableRow key={t.id} className="hover:bg-muted/30 transition-colors">
                  <TableCell className="font-medium">
                    {format(new Date(t.date), "dd/MM/yyyy")}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col">
                      <span className="font-semibold text-foreground">
                        {t.type === "TRANSFER" ? (
                          <div className="flex items-center gap-1 text-blue-600">
                            <ArrowLeftRight className="h-3 w-3" />
                            Chuyển khoản
                          </div>
                        ) : (
                          t.category?.name || "N/A"
                        )}
                      </span>
                      {t.note && <span className="text-xs text-muted-foreground line-clamp-1">{t.note}</span>}
                    </div>
                  </TableCell>
                  <TableCell>
                    {t.type === "TRANSFER" ? (
                      <div className="flex items-center gap-1 text-xs">
                        <span className="font-medium text-muted-foreground">{t.wallet?.name}</span>
                        <ArrowLeftRight className="h-3 w-3 text-muted-foreground/50" />
                        <span className="font-medium text-foreground">{t.toWallet?.name}</span>
                      </div>
                    ) : (
                      <Badge variant="outline" className="font-normal">
                        {t.wallet?.name}
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <span className={`font-bold ${t.type === "INCOME" ? "text-emerald-600" :
                      t.type === "EXPENSE" ? "text-red-600" :
                        "text-blue-600"
                      }`}>
                      {t.type === "INCOME" ? "+" : t.type === "EXPENSE" ? "-" : ""}
                      {formatCurrency(Number(t.amount))}
                    </span>
                  </TableCell>
                  <TableCell>
                    <DeleteTransactionButton transactionId={t.id} />
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {totalPages > 1 && (
        <PaginationNav currentPage={page} totalPages={totalPages} />
      )}
    </div>
  );
}
