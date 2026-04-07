import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { getBudgetsWithProgress } from "@/app/actions/budget-actions";
import { BudgetForm } from "@/components/budgets/budget-form";
import { Progress } from "@/components/ui/progress";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { TrendingUp, CheckCircle2, AlertTriangle, XCircle, Info, LayoutList } from "lucide-react";
import { redirect } from "next/navigation";
import { format } from "date-fns";
import { vi } from "date-fns/locale";
import { formatCurrency, formatCurrencyCompact } from "@/lib/utils";

export default async function BudgetsPage() {
  const session = await auth();
  const userId = session!.user!.id;

  const [budgets, categories] = await Promise.all([
    getBudgetsWithProgress(),
    prisma.category.findMany({
      where: { userId, type: 'EXPENSE', isDeleted: false },
    })
  ]);

  const currentMonth = format(new Date(), 'MMMM yyyy', { locale: vi });

  return (
    <div className="flex flex-col space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Quản lý Ngân sách</h2>
          <p className="text-muted-foreground mt-1 capitalize text-sm flex items-center gap-2">
            <LayoutList className="h-4 w-4" /> Tháng {currentMonth}
          </p>
        </div>
        <BudgetForm categories={categories} />
      </div>

      {budgets.length === 0 ? (
        <Card className="flex flex-col items-center justify-center p-16 text-center border-dashed bg-muted/20 backdrop-blur-sm">
          <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-full bg-primary/10 mb-6">
            <TrendingUp className="h-10 w-10 text-primary" />
          </div>
          <h3 className="text-2xl font-bold">Kiểm soát tài chính thông minh!</h3>
          <p className="max-w-md mt-2 text-muted-foreground">
            Bạn chưa thiết lập hạn mức ngân sách nào cho tháng này. Hãy lập kế hoạch ngay để tối ưu hóa dòng tiền của bạn.
          </p>
        </Card>
      ) : (
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {budgets.map((budget) => {
            const actualPercent = Math.round(budget.actualProgress);
            const isOverBudget = actualPercent > 100;
            const isCritical = actualPercent >= 90;
            const isWarning = actualPercent >= 70 && actualPercent < 90;

            // Dynamic color selection
            const progressColorClass = isOverBudget || isCritical
              ? "[&>div]:bg-rose-500"
              : isWarning
                ? "[&>div]:bg-amber-500"
                : "[&>div]:bg-emerald-500";

            return (
              <Card key={budget.id} className={`group overflow-hidden shadow-sm transition-all hover:shadow-xl border-none glass-effect ${isOverBudget ? 'ring-2 ring-rose-500/20' : ''}`}>
                <CardHeader className="pb-3 relative">
                  <div className="flex justify-between items-start">
                    <div className="space-y-1">
                      <CardTitle className="text-lg font-bold">
                        {budget.category?.name}
                      </CardTitle>
                      <CardDescription className="flex items-center gap-1.5 font-medium">
                        Hạn mức: <span className="text-foreground">{formatCurrency(budget.limitAmount)}</span>
                      </CardDescription>
                    </div>
                    <div className={`p-2 rounded-xl ${isOverBudget ? 'bg-rose-100 text-rose-600' : isCritical ? 'bg-rose-100 text-rose-600' : isWarning ? 'bg-amber-100 text-amber-600' : 'bg-emerald-100 text-emerald-600'}`}>
                      {isOverBudget ? (
                        <XCircle className="h-5 w-5" />
                      ) : isWarning || isCritical ? (
                        <AlertTriangle className="h-5 w-5" />
                      ) : (
                        <CheckCircle2 className="h-5 w-5" />
                      )}
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-5">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div className="space-y-1.5">
                      <p className="text-muted-foreground text-[10px] uppercase tracking-widest font-bold">Đã chi tiêu</p>
                      <p className={`font-bold text-lg ${isOverBudget ? 'text-rose-600' : 'text-primary'}`}>
                        {formatCurrency(budget.spentAmount)}
                      </p>
                    </div>
                    <div className="text-right space-y-1.5">
                      <p className="text-muted-foreground text-[10px] uppercase tracking-widest font-bold">
                        {isOverBudget ? "Vượt mức" : "Còn lại"}
                      </p>
                      <p className={`font-bold text-lg ${isOverBudget ? 'text-rose-600' : 'text-emerald-500'}`}>
                        {formatCurrency(Math.abs(budget.remainingAmount))}
                      </p>
                    </div>
                  </div>

                  <div className="space-y-2.5">
                    <div className="flex justify-between items-center">
                      <span className="text-xs font-bold text-muted-foreground uppercase tracking-tight">Sử dụng</span>
                      <span className={`text-sm font-black ${isOverBudget || isCritical ? "text-rose-600" : isWarning ? "text-amber-600" : "text-emerald-600"}`}>
                        {actualPercent}%
                      </span>
                    </div>
                    <Progress
                      value={budget.progress}
                      className={`h-3 rounded-full bg-muted shadow-inner ${progressColorClass}`}
                    />
                  </div>

                  {isOverBudget && (
                    <div className="flex items-center gap-3 p-3 rounded-xl bg-rose-500/10 text-rose-700 text-xs border border-rose-200 animate-in zoom-in-95 duration-500">
                      <Info className="h-4 w-4 shrink-0" />
                      <p className="font-medium leading-relaxed">
                        Cảnh báo: Bạn đã chi tiêu quá hạn mức cho phép.
                      </p>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
