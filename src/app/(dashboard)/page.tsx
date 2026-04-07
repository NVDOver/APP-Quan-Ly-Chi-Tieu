import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Wallet, CreditCard, ArrowRight, PlusCircle, TrendingUp, TrendingDown } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Button } from "@/components/ui/button";
import { getDashboardStats } from "@/app/actions/dashboard-actions";
import { SpendingPieChart } from "@/components/dashboard/spending-pie-chart";
import { IncomeVsExpenseChart } from "@/components/dashboard/income-expense-chart";
import { BudgetAlerts } from "@/components/dashboard/budget-alerts";
import { FadeIn } from "@/components/fade-in";
import { AIAdvisor } from "@/components/dashboard/ai-advisor";
import { formatCurrency, formatCurrencyCompact } from "@/lib/utils";

export default async function DashboardPage() {
  const session = await auth();
  const userId = session!.user!.id;

  // Thực hiện truy vấn song song (Parallel Data Fetching)
  const [wallets, categories, savingGoals, stats, dbUser] = await Promise.all([
    prisma.wallet.findMany({ where: { userId } }),
    prisma.category.findMany({ where: { userId, isDeleted: false } }),
    prisma.savingGoal.findMany({ where: { userId } }),
    getDashboardStats(),
    prisma.user.findUnique({ where: { id: userId } }),
  ]);


  // Tính tổng số dư của tất cả các ví
  const totalBalance = wallets.reduce((acc, wallet) => acc + Number(wallet.balance), 0);

  const walletCount = wallets.length;
  const categoryCount = categories.length;

  const hasData = walletCount > 0 || categoryCount > 0;

  return (
    <div className="flex flex-col space-y-8">
      <BudgetAlerts />
      <FadeIn delay={0.1}>
        <div className="flex items-center justify-between space-y-2">
          <h2 className="text-3xl font-bold tracking-tight">Tổng quan tài chính</h2>
        </div>
      </FadeIn>

      {!hasData ? (
        <FadeIn delay={0.2}>
          <Card className="flex flex-col items-center justify-center p-12 text-center border-dashed">
            <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-full bg-muted">
              <Wallet className="h-10 w-10 text-muted-foreground" />
            </div>
            <h3 className="mt-4 text-xl font-semibold">Chào mừng bạn mới đến!</h3>
            <p className="mb-4 mt-2 text-sm text-muted-foreground">
              Hệ thống hiện tại của bạn chưa có dữ liệu giao dịch. Hãy bắt đầu bằng cách cấu hình ví của bạn.
            </p>
            <Button asChild>
              <Link href="/wallets">
                <PlusCircle className="mr-2 h-4 w-4" /> Cấu hình Ví đầu tiên
              </Link>
            </Button>
          </Card>
        </FadeIn>
      ) : (
        <>
          {/* Hàng trên cùng: 3 thẻ thống kê nhanh */}
          <div className="grid gap-4 md:grid-cols-3">
            <FadeIn delay={0.1} direction="up">
              <Card className="bg-primary/5 border-primary/20 shadow-sm border-none">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Tổng tài sản thực tế</CardTitle>
                  <Wallet className="h-4 w-4 text-primary" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-primary">{formatCurrency(totalBalance)}</div>
                  <p className="text-xs text-muted-foreground mt-1">
                    Tính trên {walletCount} ví đang hoạt động
                  </p>
                </CardContent>
              </Card>
            </FadeIn>

            <FadeIn delay={0.2} direction="up">
              <Card className="shadow-sm border-none">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Số lượng Ví</CardTitle>
                  <CreditCard className="h-4 w-4 text-muted-foreground" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{walletCount} <span className="text-base font-normal text-muted-foreground">ví</span></div>
                </CardContent>
              </Card>
            </FadeIn>

            <FadeIn delay={0.3} direction="up">
              <Card className="shadow-sm border-none bg-rose-500/10 border-rose-500/20">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Chi tiêu tháng này</CardTitle>
                  <TrendingDown className="h-4 w-4 text-rose-500" />
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold text-rose-600">{formatCurrency(stats.momStats.currentExpTotal)}</div>
                  <p className="text-xs text-muted-foreground mt-1">
                    {stats.momStats.expDiffPercent >= 0 ? "+" : ""}{stats.momStats.expDiffPercent}% so với tháng trước
                  </p>
                </CardContent>
              </Card>
            </FadeIn>
          </div>

          <div className="grid gap-4 grid-cols-1 lg:grid-cols-4">
            <div className="lg:col-span-1">
              <FadeIn delay={0.4} direction="left">
                <Card className="shadow-sm border-none overflow-hidden bg-card">
                  <SpendingPieChart data={stats.pieChartData} />
                </Card>
              </FadeIn>
            </div>

            <div className="lg:col-span-2">
              <FadeIn delay={0.5} direction="up">
                <Card className="shadow-sm border-none overflow-hidden bg-card h-full">
                  <IncomeVsExpenseChart data={stats.barChartData} />
                </Card>
              </FadeIn>
            </div>

            <div className="lg:col-span-1">
              <FadeIn delay={0.6} direction="right">
                <Card className="shadow-sm border-none bg-card h-full">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-lg">Tiến độ Tiết kiệm</CardTitle>
                    <CardDescription>Các mục tiêu sắp hoàn thành</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {savingGoals.length === 0 ? (
                      <div className="text-center py-8 text-muted-foreground text-sm">Chưa có mục tiêu nào</div>
                    ) : (
                      savingGoals
                        .map(goal => ({
                          ...goal,
                          percent: Math.min(Math.round((Number(goal.currentAmount) / Number(goal.targetAmount)) * 100), 100)
                        }))
                        .sort((a, b) => b.percent - a.percent)
                        .slice(0, 3)
                        .map(goal => (
                          <div key={goal.id} className="space-y-1">
                            <div className="flex items-center justify-between text-xs">
                              <span className="font-medium truncate max-w-[120px]">{goal.name}</span>
                              <span className="text-primary font-bold">{goal.percent}%</span>
                            </div>
                            <div className="h-1.5 w-full bg-muted rounded-full overflow-hidden">
                              <div
                                className="h-full bg-primary transition-all duration-500"
                                style={{ width: `${goal.percent}%` }}
                              />
                            </div>
                          </div>
                        ))
                    )}
                  </CardContent>
                  {savingGoals.length > 0 && (
                    <CardFooter className="pt-0">
                      <Button variant="ghost" size="sm" className="w-full text-xs text-primary" asChild>
                        <Link href="/saving-goals">Tất cả mục tiêu <ArrowRight className="ml-1 h-3 w-3" /></Link>
                      </Button>
                    </CardFooter>
                  )}
                </Card>
              </FadeIn>
            </div>
          </div>

          <FadeIn delay={0.65} direction="up">
            <AIAdvisor />
          </FadeIn>

          <div className="grid gap-4 md:grid-cols-2 mt-6">
            <FadeIn delay={0.7} direction="up">
              <Card className="shadow-sm border-none h-full">
                <CardHeader>
                  <CardTitle className="text-lg">Tài khoản & Ví</CardTitle>
                  <CardDescription>Cơ cấu sổ tài khoản của bạn</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    {wallets.length === 0 ? (
                      <div className="text-center py-8 text-muted-foreground text-sm">Chưa có ví nào</div>
                    ) : (
                      wallets.slice(0, 5).map((wallet) => (
                        <div key={wallet.id} className="flex items-center">
                          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10 mr-4">
                            <Wallet className="h-5 w-5 text-primary" />
                          </div>
                          <div className="ml-4 space-y-1 overflow-hidden">
                            <p className="text-sm font-medium leading-none truncate">{wallet.name}</p>
                          </div>
                          <div className="ml-auto font-medium text-sm text-right">
                            {formatCurrency(Number(wallet.balance))}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </CardContent>
                {wallets.length > 5 && (
                  <CardFooter>
                    <Button variant="ghost" size="sm" className="w-full text-xs text-muted-foreground" asChild>
                      <Link href="/wallets">Xem tất cả (<ArrowRight className="ml-1 inline h-3 w-3" />)</Link>
                    </Button>
                  </CardFooter>
                )}
              </Card>
            </FadeIn>

            <FadeIn delay={0.8} direction="up">
              <Card className="shadow-sm border-none h-full">
                <CardHeader>
                  <CardTitle className="text-lg">Danh mục phổ biến</CardTitle>
                  <CardDescription>Hệ thống phân loại dòng tiền</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-6">
                    {categories.length === 0 ? (
                      <div className="text-center py-8 text-muted-foreground text-sm">Chưa có danh mục nào</div>
                    ) : (
                      categories.slice(0, 5).map((category) => (
                        <div key={category.id} className="flex items-center">
                          <div className={`flex h-10 w-10 items-center justify-center rounded-full mr-4 ${category.type === 'INCOME'
                            ? 'bg-green-100 dark:bg-green-900/20'
                            : 'bg-rose-100 dark:bg-rose-900/20'
                            }`}
                          >
                            {category.type === 'INCOME' ? (
                              <TrendingUp className="h-5 w-5 text-green-600 dark:text-green-500" />
                            ) : (
                              <TrendingDown className="h-5 w-5 text-rose-600 dark:text-rose-500" />
                            )}
                          </div>
                          <div className="ml-4 space-y-1">
                            <p className="text-sm font-medium leading-none truncate">{category.name}</p>
                            <p className="text-xs text-muted-foreground">
                              {category.type === 'INCOME' ? 'Thu nhập' : 'Chi tiêu'}
                            </p>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </CardContent>
                {categories.length > 5 && (
                  <CardFooter>
                    <Button variant="ghost" size="sm" className="w-full text-xs text-muted-foreground" asChild>
                      <Link href="/categories">Xem tất cả (<ArrowRight className="ml-1 inline h-3 w-3" />)</Link>
                    </Button>
                  </CardFooter>
                )}
              </Card>
            </FadeIn>
          </div>
        </>
      )}
    </div>
  );
}
