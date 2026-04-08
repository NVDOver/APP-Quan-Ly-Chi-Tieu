"use client";

import { DebtLoan, Transaction, Wallet } from "@prisma/client";
import { formatCurrency } from "@/lib/utils";
import { format } from "date-fns";
import { 
  Calendar, 
  User, 
  Wallet as WalletIcon, 
  Info, 
  CheckCircle2, 
  Clock,
  MoreVertical,
  Trash2
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { 
    DropdownMenu, 
    DropdownMenuContent, 
    DropdownMenuItem, 
    DropdownMenuTrigger 
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { RepaymentForm } from "./repayment-form";
import { deleteDebtLoan } from "@/app/actions/debt-loan-actions";
import { toast } from "sonner";

interface DebtLoanWithRelations extends DebtLoan {
    wallet: Wallet;
    transactions: Transaction[];
}

interface DebtLoanListProps {
  items: DebtLoanWithRelations[];
}

export function DebtLoanList({ items }: DebtLoanListProps) {
  if (items.length === 0) {
    return (
      <div className="flex min-h-[400px] flex-col items-center justify-center rounded-lg border border-dashed text-center">
        <Info className="mb-4 h-10 w-10 text-muted-foreground" />
        <h3 className="text-lg font-medium">Không có bản ghi nào</h3>
        <p className="text-sm text-muted-foreground">
          Hãy tạo khoản vay hoặc cho mượn đầu tiên của bạn.
        </p>
      </div>
    );
  }

  const handleDelete = async (id: string) => {
    if (confirm("Bạn có chắc chắn muốn xoá bản ghi này? Các giao dịch liên quan sẽ không bị xoá.")) {
        const res = await deleteDebtLoan(id);
        if (res.success) {
            toast.success("Đã xoá thành công");
        } else {
            toast.error(res.error || "Có lỗi xảy ra");
        }
    }
  }

  return (
    <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
      {items.map((item) => {
        const paidAmount = Number(item.amount) - Number(item.remainingAmount);
        const progress = (paidAmount / Number(item.amount)) * 100;
        const isDebt = item.type === "DEBT";

        return (
          <Card key={item.id} className="overflow-hidden transition-all hover:shadow-md">
            <CardHeader className="pb-4">
              <div className="flex items-start justify-between">
                <Badge 
                  variant={isDebt ? "destructive" : "secondary"}
                  className={!isDebt ? "bg-green-100 text-green-700 hover:bg-green-200 dark:bg-green-900/30 dark:text-green-400" : ""}
                >
                  {isDebt ? "Tôi đi vay" : "Tôi cho vay"}
                </Badge>
                <div className="flex items-center gap-2">
                    {item.status === "PAID" ? (
                    <Badge variant="outline" className="text-green-600 border-green-200 bg-green-50 dark:bg-green-950/20">
                        <CheckCircle2 className="mr-1 h-3 w-3" />
                        Đã xong
                    </Badge>
                    ) : (
                    <Badge variant="outline" className="text-amber-600 border-amber-200 bg-amber-50 dark:bg-amber-950/20">
                        <Clock className="mr-1 h-3 w-3" />
                        Đang nợ
                    </Badge>
                    )}
                    <DropdownMenu>
                      <DropdownMenuTrigger
                        render={
                          <Button variant="ghost" size="icon" className="h-8 w-8">
                            <MoreVertical className="h-4 w-4" />
                          </Button>
                        }
                      />
                      <DropdownMenuContent align="end">
                            <DropdownMenuItem 
                                className="text-destructive focus:text-destructive"
                                onClick={() => handleDelete(item.id)}
                            >
                                <Trash2 className="mr-2 h-4 w-4" />
                                Xoá bản ghi
                            </DropdownMenuItem>
                        </DropdownMenuContent>
                    </DropdownMenu>
                </div>
              </div>
              <CardTitle className="mt-2 text-xl">{formatCurrency(Number(item.amount))}</CardTitle>
              <CardDescription className="flex items-center gap-1">
                <User className="h-3 w-3" />
                {item.personName}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Tiến độ trả nợ</span>
                  <span className="font-medium">{progress.toFixed(0)}%</span>
                </div>
                <Progress value={progress} className="h-2" />
                <div className="flex justify-between text-[10px] text-muted-foreground">
                  <span>Còn nợ: {formatCurrency(Number(item.remainingAmount))}</span>
                  <span>Đã trả: {formatCurrency(paidAmount)}</span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4 text-xs">
                <div className="flex items-center gap-2">
                  <WalletIcon className="h-3 w-3 text-muted-foreground" />
                  <span className="truncate">{item.wallet.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Calendar className="h-3 w-3 text-muted-foreground" />
                  <span>{format(new Date(item.startDate), "dd/MM/yyyy")}</span>
                </div>
              </div>

              {item.dueDate && (
                <div className="flex items-center gap-2 rounded-md bg-muted/50 p-2 text-xs">
                    <Clock className="h-3 w-3 text-red-500" />
                    <span className="font-medium">
                        Hạn: {format(new Date(item.dueDate), "dd/MM/yyyy")}
                    </span>
                </div>
              )}

              {item.status === "OPEN" && (
                <RepaymentForm debtLoan={item} />
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
