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
import { formatCurrency } from "@/lib/utils";
import type { Transaction, Wallet, Category } from "@prisma/client";
import { FadeIn } from "@/components/fade-in";
import { ExportButton } from "@/components/transactions/export-button";

// Wallet với balance đã được serialize sang number
type SerializedWallet = Omit<Wallet, "balance"> & { balance: number };

// Type chính xác từ Prisma (thay vì any)
type TransactionWithRelations = Omit<Transaction, "amount"> & {
  amount: number;
  wallet: SerializedWallet;
  toWallet: SerializedWallet | null;
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

  const [
    { transactions, totalPages },
    { wallets }
  ] = await Promise.all([
    getTransactions({
      page,
      pageSize: 10,
      type,
      walletId
    }),
    getFormOptions()
  ]);

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-10">
      <FadeIn delay={0.1}>
        <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-gradient">Quản lý giao dịch</h1>
            <p className="text-muted-foreground"> Xem và quản lý lịch sử thu chi của bạn. </p>
          </div>
          <ExportButton data={transactions} />
        </div>
      </FadeIn>

      <FadeIn delay={0.2} direction="up">
        <div className="glass-card rounded-2xl border p-4">
          <div className="mb-4 flex items-center gap-2 font-semibold text-primary">
            <Filter className="h-4 w-4" />
            Bộ lọc nâng cao
          </div>
          <TransactionFilters wallets={wallets} currentType={type} currentWalletId={walletId} />
        </div>
      </FadeIn>

      <FadeIn delay={0.3} direction="up">
        <div className="glass-card rounded-2xl border overflow-hidden">
          <Table>
            <TableHeader className="bg-muted/30">
              <TableRow>
                <TableHead className="w-[120px]">Ngày</TableHead>
                <TableHead>Danh mục / Mô tả</TableHead>
                <TableHead className="hidden md:table-cell">Ví</TableHead>
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
                  <TableRow key={t.id} className="hover:bg-primary/5 transition-colors group">
                    <TableCell className="font-medium text-xs md:text-sm">
                      {format(new Date(t.date), "dd/MM/yyyy")}
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-bold text-foreground">
                          {t.type === "TRANSFER" ? (
                            <div className="flex items-center gap-1 text-blue-500">
                              <ArrowLeftRight className="h-3 w-3" />
                              Chuyển khoản
                            </div>
                          ) : (
                            t.category?.name || "N/A"
                          )}
                        </span>
                        {t.note && <span className="text-[10px] md:text-xs text-muted-foreground line-clamp-1">{t.note}</span>}
                        <div className="md:hidden mt-0.5">
                           <Badge variant="outline" className="text-[9px] px-1 py-0 h-4">{t.wallet?.name}</Badge>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      {t.type === "TRANSFER" ? (
                        <div className="flex items-center gap-1 text-xs">
                          <span className="font-medium text-muted-foreground">{t.wallet?.name}</span>
                          <ArrowLeftRight className="h-3 w-3 text-muted-foreground/50" />
                          <span className="font-medium text-foreground">{t.toWallet?.name}</span>
                        </div>
                      ) : (
                        <Badge variant="outline" className="font-medium text-xs">
                          {t.wallet?.name}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <span className={`font-black text-sm md:text-base ${
                        t.type === "INCOME" ? "text-emerald-500" :
                        t.type === "EXPENSE" ? "text-rose-500" :
                        "text-blue-500"
                      }`}>
                        {t.type === "INCOME" ? "+" : t.type === "EXPENSE" ? "-" : ""}
                        {formatCurrency(Number(t.amount))}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="opacity-0 group-hover:opacity-100 transition-opacity">
                        <DeleteTransactionButton transactionId={t.id} />
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </FadeIn>

      <FadeIn delay={0.4}>
        {totalPages > 1 && (
          <PaginationNav currentPage={page} totalPages={totalPages} />
        )}
      </FadeIn>
    </div>
  );
}
