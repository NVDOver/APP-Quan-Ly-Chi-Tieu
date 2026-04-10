import { auth } from "@/lib/auth";
import { getDashboardChartData } from "@/app/actions/dashboard-actions";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SpendingPieChart } from "@/components/dashboard/spending-pie-chart";
import { IncomeVsExpenseChart } from "@/components/dashboard/income-expense-chart";
import { FadeIn } from "@/components/fade-in";

export async function ChartsSection() {
  // auth() is cached by Next.js if called in the same request
  const session = await auth();
  if (!session?.user?.id) return null;

  const stats = await getDashboardChartData();

  return (
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
  );
}
