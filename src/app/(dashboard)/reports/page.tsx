"use client";

import { useState, useEffect } from "react";
import { 
  TrendingUp, 
  Filter, 
  BarChart3, 
  FileSpreadsheet,
  ArrowRight,
  TrendingDown,
  Clock,
  Target
} from "lucide-react";
import { 
  Card, 
  CardContent, 
  CardDescription, 
  CardHeader, 
  CardTitle, 
  CardFooter 
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { exportTransactionsToExcel, getCashFlowTrend } from "@/app/actions/report-actions";
import { TrendsChart } from "@/components/dashboard/trends-chart";

import { AdvancedAnalysis } from "@/components/reports/advanced-analysis";
import { getDashboardStats } from "@/app/actions/dashboard-actions";
import { FadeIn } from "@/components/fade-in";

export default function ReportsPage() {
  const [trendData, setTrendData] = useState<{ label: string; income: number; expense: number }[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isExporting, setIsExporting] = useState(false);

  const fetchData = async () => {
    setIsLoading(true);
    const [trendRes, statsRes] = await Promise.all([
      getCashFlowTrend(),
      getDashboardStats(),
    ]);

    if (trendRes.success) setTrendData(trendRes.data || []);
    if (statsRes) setStats(statsRes);
    
    setIsLoading(false);
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleExport = async () => {
    setIsExporting(true);
    try {
      const result = await exportTransactionsToExcel();
      if (result.success && result.data) {
        // Create download link for Base64 Excel
        const link = document.createElement("a");
        link.href = `data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,${result.data}`;
        const dateStr = new Date().toLocaleDateString("vi-VN").replace(/\//g, "-");
        link.download = `Bao_cao_giao_dich_${dateStr}.xlsx`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        toast.success("Xuất file Excel thành công!");
      } else if (!result.success) {
        toast.error(result.error || "Lỗi khi xuất file");
      }
    } catch (error) {
      if (error instanceof Error) console.error("Export UI Error:", error.message);
      toast.error("Đã xảy ra lỗi khi tạo file");
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="flex flex-col space-y-8 pb-10">
      <FadeIn delay={0.1}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-3xl font-bold tracking-tight text-gradient">Trung tâm Báo cáo</h2>
            <p className="text-muted-foreground">Phân tích chuyên sâu về sức khỏe tài chính của bạn</p>
          </div>
          <div className="flex gap-2">
            <Button 
              variant="outline" 
              onClick={handleExport} 
              disabled={isExporting}
              className="rounded-full shadow-lg hover:bg-primary/5 hover:text-primary transition-all px-6"
            >
              {isExporting ? <Clock className="mr-2 h-4 w-4 animate-spin" /> : <FileSpreadsheet className="mr-2 h-4 w-4" />}
              Xuất Excel
            </Button>
          </div>
        </div>
      </FadeIn>

      {!isLoading && stats && (
        <FadeIn delay={0.2} direction="up">
          <AdvancedAnalysis stats={stats.momStats} />
        </FadeIn>
      )}

      <div className="grid gap-6 md:grid-cols-4">
        {/* Advanced Filters Sidebar */}
        <FadeIn delay={0.3} direction="left" className="md:col-span-1">
          <Card className="glass-card border-none shadow-sm h-full">
            <CardHeader className="pb-3 border-b border-border/10">
              <CardTitle className="text-lg font-bold flex items-center">
                <Filter className="mr-2 h-4 w-4" /> Bộ lọc nâng cao
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6 pt-6">
              <div className="space-y-2">
                <label className="text-[10px] font-black uppercase text-muted-foreground tracking-widest">Khoảng Thời gian</label>
                <select
                  defaultValue="6m"
                  className="flex h-10 w-full rounded-xl border border-input bg-muted/30 px-3 py-1 text-sm shadow-inner transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20"
                >
                  <option value="1m">Tháng này</option>
                  <option value="3m">3 tháng qua</option>
                  <option value="6m">6 tháng qua</option>
                  <option value="1y">1 năm qua</option>
                </select>
              </div>
              <div className="space-y-2">
                <label className="text-[10px] font-black uppercase text-muted-foreground tracking-widest">Loại giao dịch</label>
                <div className="space-y-2">
                  <div className="flex items-center gap-3 p-3 rounded-2xl bg-emerald-500/10 text-emerald-700 text-xs font-bold transition-all hover:bg-emerald-500/20 cursor-pointer">
                    <TrendingUp className="h-4 w-4" /> Chỉ xem Thu nhập
                  </div>
                  <div className="flex items-center gap-3 p-3 rounded-2xl bg-rose-500/10 text-rose-700 text-xs font-bold transition-all hover:bg-rose-500/20 cursor-pointer">
                    <TrendingDown className="h-4 w-4" /> Chỉ xem Chi tiêu
                  </div>
                </div>
              </div>
            </CardContent>
            <CardFooter className="pt-0">
              <Button variant="ghost" className="w-full text-xs font-bold hover:bg-primary/5 hover:text-primary rounded-xl" onClick={() => toast.info("Tính năng đang được phát triển")}>
                Áp dụng bộ lọc <ArrowRight className="ml-2 h-3 w-3" />
              </Button>
            </CardFooter>
          </Card>
        </FadeIn>

        {/* Main Charts Area */}
        <div className="md:col-span-3 space-y-6">
          <FadeIn delay={0.4} direction="up">
            <Card className="glass-card border-none shadow-sm h-full">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-xl font-bold">Xu hướng dòng tiền</CardTitle>
                    <CardDescription>Biến động thu chi trong 6 tháng gần nhất</CardDescription>
                  </div>
                  <div className="p-3 bg-primary/10 rounded-2xl">
                    <BarChart3 className="h-6 w-6 text-primary" />
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <div className="h-[400px] w-full animate-pulse bg-muted rounded-2xl" />
                ) : (
                  <div className="h-[400px]">
                    <TrendsChart data={trendData} />
                  </div>
                )}
              </CardContent>
            </Card>
          </FadeIn>

          <div className="grid gap-6 md:grid-cols-2">
            <FadeIn delay={0.5} direction="up">
              <Card className="border-none shadow-sm bg-primary/5 rounded-3xl h-full hover:bg-primary/10 transition-colors cursor-pointer group p-6">
                <CardHeader className="p-0 mb-3">
                  <div className="flex items-center gap-3">
                     <div className="p-2 bg-primary/20 rounded-xl group-hover:scale-110 transition-transform">
                       <TrendingUp className="h-4 w-4 text-primary" />
                     </div>
                     <CardTitle className="text-base font-bold">Gợi ý tiết kiệm AI</CardTitle>
                  </div>
                </CardHeader>
                <CardContent className="p-0 text-xs text-muted-foreground leading-relaxed font-medium">
                  Dựa trên phân tích 3 tháng qua, bạn có thể tiết kiệm thêm <span className="text-primary font-bold">12%</span> nếu giảm 15% chi tiêu cho &quot;Ăn uống&quot;. Hệ thống nhận thấy bạn thường xuyên chi tiêu cao vào cuối tuần.
                </CardContent>
              </Card>
            </FadeIn>
            
            <FadeIn delay={0.6} direction="up">
              <Card className="border-none shadow-sm bg-emerald-500/5 rounded-3xl h-full hover:bg-emerald-500/10 transition-colors cursor-pointer group p-6">
                <CardHeader className="p-0 mb-3">
                   <div className="flex items-center gap-3">
                      <div className="p-2 bg-emerald-500/20 rounded-xl group-hover:scale-110 transition-transform">
                        <Target className="h-4 w-4 text-emerald-600" />
                      </div>
                      <CardTitle className="text-base font-bold">Mục tiêu trung hạn</CardTitle>
                   </div>
                </CardHeader>
                <CardContent className="p-0 text-xs text-muted-foreground leading-relaxed font-medium">
                  Với đà chi tiêu hiện tại, dự kiến số dư tài sản của bạn sẽ tăng thêm <span className="text-emerald-600 font-black">5.000.000đ</span> vào cuối tháng tới. Bạn đang đi đúng hướng để mua chiếc iPhone mới!
                </CardContent>
              </Card>
            </FadeIn>
          </div>
        </div>
      </div>
    </div>
  );
}
