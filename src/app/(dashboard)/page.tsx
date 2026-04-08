import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Wallet, CreditCard, ArrowRight, PlusCircle, TrendingUp, TrendingDown, Target } from "lucide-react";
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
  const [rawWallets, categories, savingGoals, stats, dbUser] = await Promise.all([
    prisma.wallet.findMany({ where: { userId } }),
    prisma.category.findMany({ where: { userId, isDeleted: false } }),
    prisma.savingGoal.findMany({ where: { userId } }),
    getDashboardStats(),
    prisma.user.findUnique({ where: { id: userId } }),
  ]);

  // Serialize Decimal → number để tránh lỗi khi truyền sang Client Components
  const wallets = rawWallets.map((w) => ({ ...w, balance: Number(w.balance) }));
  const serializedSavingGoals = savingGoals.map((g) => ({
    ...g,
    targetAmount: Number(g.targetAmount),
    currentAmount: Number(g.currentAmount),
  }));


  // Tính tổng số dư của tất cả các ví
  const totalBalance = wallets.reduce((acc, wallet) => acc + Number(wallet.balance), 0);

  const walletCount = wallets.length;
  const categoryCount = categories.length;

  const hasData = walletCount > 0 || categoryCount > 0;

  // Render Greeting
  const getGreeting = () => {
    const hour = new Date().getHours();
    if (hour < 12) return "Chào buổi sáng";
    if (hour < 18) return "Chào buổi chiều";
    return "Chào buổi tối";
  };

  const currentDate = new Intl.DateTimeFormat('vi-VN', { 
    weekday: 'long', 
    year: 'numeric', 
    month: 'long', 
    day: 'numeric' 
  }).format(new Date());

  return (
    <div className="flex flex-col space-y-10 pb-10">
      <BudgetAlerts />
      
      {/* Header Chào mừng / Welcome Section */}
      <FadeIn delay={0.1}>
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
          <div className="space-y-1">
            <p className="text-sm font-medium text-muted-foreground uppercase tracking-widest">{currentDate}</p>
            <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight">
              {getGreeting()}, <span className="text-gradient">{dbUser?.fullName || 'Bạn'}</span> 👋
            </h1>
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" className="rounded-full shadow-lg shadow-primary/20" asChild>
              <Link href="/transactions">
                <PlusCircle className="mr-2 h-4 w-4" /> Giao dịch mới
              </Link>
            </Button>
          </div>
        </div>
      </FadeIn>

      {!hasData ? (
        <FadeIn delay={0.2}>
          <Card className="glass-card flex flex-col items-center justify-center p-16 text-center border-dashed">
            <div className="mx-auto flex h-24 w-24 items-center justify-center rounded-3xl bg-primary/10 shadow-inner">
              <Wallet className="h-12 w-12 text-primary animate-pulse" />
            </div>
            <h3 className="mt-6 text-2xl font-bold">Bắt đầu hành trình tài chính</h3>
            <p className="mb-6 mt-3 text-muted-foreground max-w-sm mx-auto">
              Chào mừng bạn đến với SpendWise. Hãy tạo chiếc ví đầu tiên để chúng tôi giúp bạn quản lý dòng tiền nhé!
            </p>
            <Button size="lg" className="rounded-full px-8" asChild>
              <Link href="/wallets">
                Khởi tạo ngay <ArrowRight className="ml-2 h-4 w-4" />
              </Link>
            </Button>
          </Card>
        </FadeIn>
      ) : (
        <>
          {/* Dashboard Stats Grid */}
          <div className="grid gap-6 md:grid-cols-3">
            <FadeIn delay={0.15} direction="up">
              <div className="premium-card relative group rounded-3xl p-6 bg-gradient-to-br from-emerald-600 to-teal-700 text-white shadow-xl shadow-emerald-500/20 overflow-hidden h-full">
                <div className="absolute -right-4 -top-4 opacity-10 group-hover:scale-110 transition-transform duration-500">
                  <Wallet size={120} />
                </div>
                <p className="text-emerald-100/80 text-sm font-semibold uppercase tracking-wider mb-2">Tổng tài sản thực tế</p>
                <h3 className="text-3xl font-black mb-4 tracking-tight">{formatCurrency(totalBalance)}</h3>
                <div className="flex items-center gap-2 text-xs text-emerald-100/60 bg-white/10 w-fit px-3 py-1 rounded-full backdrop-blur-md">
                  <Wallet size={12} />
                  <span>{walletCount} ví đang hoạt động</span>
                </div>
              </div>
            </FadeIn>

            <FadeIn delay={0.25} direction="up">
              <div className="glass-card premium-card rounded-3xl p-6 h-full">
                 <div className="flex justify-between items-start mb-4">
                    <div className="p-3 bg-primary/10 rounded-2xl text-primary">
                      <CreditCard size={24} />
                    </div>
                    <span className="text-xs font-bold text-muted-foreground uppercase">Ví & Tài khoản</span>
                 </div>
                 <p className="text-muted-foreground text-sm font-medium mb-1">Số lượng ví</p>
                 <h3 className="text-3xl font-extrabold">{walletCount} <span className="text-lg font-normal text-muted-foreground">tài khoản</span></h3>
              </div>
            </FadeIn>

            <FadeIn delay={0.35} direction="up">
              <div className="glass-card premium-card rounded-3xl p-6 h-full border-rose-500/10">
                 <div className="flex justify-between items-start mb-4">
                    <div className="p-3 bg-rose-500/10 rounded-2xl text-rose-500">
                      <TrendingDown size={24} />
                    </div>
                    <span className="text-xs font-bold text-rose-500/70 uppercase">Chi tiêu tháng</span>
                 </div>
                 <p className="text-muted-foreground text-sm font-medium mb-1">Tháng hiện tại</p>
                 <h3 className="text-3xl font-extrabold text-rose-500">{formatCurrency(stats.momStats.currentExpTotal || 0)}</h3>
                 <div className={`mt-2 flex items-center gap-1 text-xs font-bold ${stats.momStats.expDiffPercent >= 0 ? 'text-rose-500' : 'text-emerald-500'}`}>
                    {stats.momStats.expDiffPercent >= 0 ? <TrendingUp size={12} /> : <TrendingDown size={12} />}
                    {Math.abs(stats.momStats.expDiffPercent)}% so với tháng trước
                 </div>
              </div>
            </FadeIn>
          </div>

          <div className="grid gap-6 grid-cols-1 lg:grid-cols-12">
            <div className="lg:col-span-4">
              <FadeIn delay={0.45} direction="left">
                <Card className="glass-card premium-card rounded-3xl overflow-hidden h-full border-none shadow-lg">
                  <CardHeader className="pb-0">
                    <CardTitle className="text-lg font-bold">Phân bổ Chi tiêu</CardTitle>
                    <CardDescription>Theo danh mục (30 ngày)</CardDescription>
                  </CardHeader>
                  <SpendingPieChart data={stats.pieChartData} />
                </Card>
              </FadeIn>
            </div>

            <div className="lg:col-span-8">
              <FadeIn delay={0.55} direction="right">
                <Card className="glass-card premium-card rounded-3xl overflow-hidden h-full border-none shadow-lg">
                  <CardHeader className="pb-0">
                    <CardTitle className="text-lg font-bold">Xu hướng Tài chính</CardTitle>
                    <CardDescription>So sánh thu nhập & chi tiêu</CardDescription>
                  </CardHeader>
                  <IncomeVsExpenseChart data={stats.barChartData} />
                </Card>
              </FadeIn>
            </div>
          </div>

          <div className="grid gap-6 grid-cols-1 lg:grid-cols-2">
            <FadeIn delay={0.65} direction="up">
              <div className="h-full">
                <AIAdvisor />
              </div>
            </FadeIn>

            <FadeIn delay={0.7} direction="up">
              <Card className="glass-card premium-card rounded-3xl h-full border-none shadow-lg">
                <CardHeader>
                  <CardTitle className="text-lg font-bold">Mục tiêu Tiết kiệm</CardTitle>
                  <CardDescription>Hành trình đạt được giấc mơ của bạn</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  {serializedSavingGoals.length === 0 ? (
                    <div className="flex flex-col items-center py-10 opacity-40">
                      <Target size={40} className="mb-2" />
                      <p className="text-sm">Chưa có mục tiêu nào</p>
                    </div>
                  ) : (
                    serializedSavingGoals
                      .map(goal => ({
                        ...goal,
                        percent: Math.min(Math.round((goal.currentAmount / goal.targetAmount) * 100), 100)
                      }))
                      .sort((a, b) => b.percent - a.percent)
                      .slice(0, 3)
                      .map(goal => (
                        <div key={goal.id} className="space-y-2">
                          <div className="flex items-center justify-between text-sm">
                            <span className="font-bold truncate max-w-[200px]">{goal.name}</span>
                            <span className="text-emerald-500 font-black">{goal.percent}%</span>
                          </div>
                          <div className="h-3 w-full bg-muted rounded-full overflow-hidden shadow-inner">
                            <div
                              className="h-full bg-gradient-to-r from-primary to-emerald-400 rounded-full transition-all duration-1000"
                              style={{ width: `${goal.percent}%` }}
                            />
                          </div>
                          <div className="flex justify-between text-[10px] text-muted-foreground font-medium uppercase tracking-tighter">
                            <span>Đã tích lũy {formatCurrencyCompact(goal.currentAmount)}</span>
                            <span>Mục tiêu {formatCurrencyCompact(goal.targetAmount)}</span>
                          </div>
                        </div>
                      ))
                  )}
                </CardContent>
                {serializedSavingGoals.length > 0 && (
                  <CardFooter className="pt-0 border-t border-border/10">
                    <Button variant="ghost" size="sm" className="w-full mt-2 group" asChild>
                      <Link href="/saving-goals" className="flex items-center justify-center">
                        Xem tất cả kế hoạch <ArrowRight className="ml-2 h-4 w-4 transition-transform group-hover:translate-x-1" />
                      </Link>
                    </Button>
                  </CardFooter>
                )}
              </Card>
            </FadeIn>
          </div>

          <div className="grid gap-6 md:grid-cols-2">
            {/* Wallet List Card */}
            <FadeIn delay={0.75} direction="up">
              <Card className="glass-card premium-card rounded-3xl border-none shadow-lg">
                <CardHeader className="flex flex-row items-center justify-between">
                  <div>
                    <CardTitle className="text-lg font-bold">Danh sách Ví</CardTitle>
                    <CardDescription>Quản lý các nguồn tiền</CardDescription>
                  </div>
                  <Button variant="outline" size="icon" className="rounded-xl" asChild>
                    <Link href="/wallets"><PlusCircle className="h-4 w-4" /></Link>
                  </Button>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {wallets.length === 0 ? (
                      <div className="text-center py-6 text-muted-foreground italic">Trống</div>
                    ) : (
                      wallets.slice(0, 4).map((wallet) => (
                        <div key={wallet.id} className="group flex items-center p-3 rounded-2xl hover:bg-accent/50 transition-colors">
                          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-primary/10 text-primary shadow-inner">
                            <Wallet className="h-6 w-6" />
                          </div>
                          <div className="ml-4 flex-1 overflow-hidden">
                            <p className="text-sm font-bold truncate tracking-tight">{wallet.name}</p>
                            <p className="text-[10px] text-muted-foreground uppercase font-medium">Hoạt động</p>
                          </div>
                          <div className="text-right">
                             <p className="text-sm font-black text-primary">{formatCurrency(Number(wallet.balance))}</p>
                             <div className="h-1 w-12 bg-primary/20 rounded-full ml-auto mt-1" />
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </CardContent>
              </Card>
            </FadeIn>

            {/* Recent Categories/Activity */}
            <FadeIn delay={0.8} direction="up">
              <Card className="glass-card premium-card rounded-3xl border-none shadow-lg">
                <CardHeader>
                  <CardTitle className="text-lg font-bold">Phân loại Dòng tiền</CardTitle>
                  <CardDescription>Các danh mục giao dịch</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {categories.length === 0 ? (
                      <div className="text-center py-6 text-muted-foreground italic">Trống</div>
                    ) : (
                      categories.slice(0, 4).map((category) => (
                        <div key={category.id} className="flex items-center p-3 rounded-2xl hover:bg-accent/50 transition-colors">
                          <div className={`flex h-12 w-12 items-center justify-center rounded-2xl shadow-inner ${
                            category.type === 'INCOME' 
                              ? 'bg-emerald-500/10 text-emerald-500' 
                              : 'bg-rose-500/10 text-rose-500'
                          }`}>
                            {category.type === 'INCOME' ? <TrendingUp size={24} /> : <TrendingDown size={24} />}
                          </div>
                          <div className="ml-4 flex-1">
                            <p className="text-sm font-bold">{category.name}</p>
                            <p className="text-[10px] text-muted-foreground uppercase font-medium">
                              {category.type === 'INCOME' ? 'Thu nhập' : 'Chi tiêu'}
                            </p>
                          </div>
                          <div className="p-2">
                             <div className={`h-2 w-2 rounded-full ${category.type === 'INCOME' ? 'bg-emerald-500' : 'bg-rose-500'} animate-pulse`} />
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </CardContent>
              </Card>
            </FadeIn>
          </div>
        </>
      )}
    </div>
  );
}
