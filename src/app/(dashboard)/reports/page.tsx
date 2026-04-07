"use client";

import { useState, useEffect } from "react";
import { 
  TrendingUp, 
  Filter, 
  BarChart3, 
  FileSpreadsheet,
  ArrowRight,
  TrendingDown,
  Clock
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
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from "@/components/ui/select";

export default function ReportsPage() {
  const [trendData, setTrendData] = useState<{ label: string; income: number; expense: number }[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isExporting, setIsExporting] = useState(false);

  const fetchTrend = async () => {
    setIsLoading(true);
    const result = await getCashFlowTrend();
    if (result.success) {
      setTrendData(result.data || []);
    } else {
      toast.error(result.error || "Đã xảy ra lỗi");
    }
    setIsLoading(false);
  };

  useEffect(() => {
    fetchTrend();
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
    <div className="space-y-8 animate-in fade-in duration-700">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Trung tâm Báo cáo</h2>
          <p className="text-muted-foreground">Phân tích chuyên sâu về sức khỏe tài chính của bạn</p>
        </div>
        <div className="flex gap-2">
           <Button 
            variant="outline" 
            onClick={handleExport} 
            disabled={isExporting}
            className="rounded-full shadow-sm"
          >
            {isExporting ? (
              <Clock className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <FileSpreadsheet className="mr-2 h-4 w-4 text-green-600" />
            )}
            Xuất Excel
          </Button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-4">
        {/* Advanced Filters Sidebar (Conceptual for now) */}
        <Card className="md:col-span-1 glass-effect border-none shadow-sm">
          <CardHeader>
            <CardTitle className="text-lg flex items-center">
              <Filter className="mr-2 h-4 w-4" /> Bộ lọc nâng cao
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
             <div className="space-y-2">
               <label className="text-xs font-semibold uppercase text-muted-foreground">Thời gian</label>
               <Select defaultValue="6m">
                 <SelectTrigger>
                   <SelectValue placeholder="Chọn khoảng thời gian" />
                 </SelectTrigger>
                 <SelectContent>
                   <SelectItem value="1m">Tháng này</SelectItem>
                   <SelectItem value="3m">3 tháng qua</SelectItem>
                   <SelectItem value="6m">6 tháng qua</SelectItem>
                   <SelectItem value="1y">1 năm qua</SelectItem>
                 </SelectContent>
               </Select>
             </div>
             <div className="space-y-2">
               <label className="text-xs font-semibold uppercase text-muted-foreground">Trạng thái</label>
               <div className="space-y-2">
                 <div className="flex items-center gap-2 p-2 rounded-lg bg-green-500/10 text-green-700 text-sm">
                   <TrendingUp className="h-4 w-4" /> Chỉ xem Thu nhập
                 </div>
                 <div className="flex items-center gap-2 p-2 rounded-lg bg-rose-500/10 text-rose-700 text-sm">
                   <TrendingDown className="h-4 w-4" /> Chỉ xem Chi tiêu
                 </div>
               </div>
             </div>
          </CardContent>
          <CardFooter>
            <Button variant="ghost" className="w-full text-xs" onClick={() => toast.info("Tính năng đang được phát triển")}>
              Áp dụng bộ lọc <ArrowRight className="ml-2 h-3 w-3" />
            </Button>
          </CardFooter>
        </Card>

        {/* Main Charts Area */}
        <div className="md:col-span-3 space-y-6">
          <Card className="border-none shadow-sm bg-card/60 backdrop-blur-md">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Xu hướng dòng tiền (Cash Flow Trend)</CardTitle>
                  <CardDescription>Biến động thu chi trong 6 tháng gần nhất</CardDescription>
                </div>
                <div className="p-2 bg-primary/10 rounded-full">
                  <BarChart3 className="h-5 w-5 text-primary" />
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="h-[400px] w-full animate-pulse bg-muted rounded-xl" />
              ) : (
                <TrendsChart data={trendData} />
              )}
            </CardContent>
          </Card>

          <div className="grid gap-6 md:grid-cols-2">
             <Card className="border-none shadow-sm bg-primary/5">
                <CardHeader>
                  <CardTitle className="text-base">Gợi ý tiết kiệm</CardTitle>
                </CardHeader>
                <CardContent className="text-sm text-muted-foreground">
                  Dựa trên phân tích 3 tháng qua, bạn có thể tiết kiệm thêm 12% nếu giảm 15% chi tiêu cho &quot;Ăn uống&quot;.
                </CardContent>
             </Card>
             <Card className="border-none shadow-sm bg-secondary/5">
                <CardHeader>
                  <CardTitle className="text-base">Dự báo tài chính</CardTitle>
                </CardHeader>
                <CardContent className="text-sm text-muted-foreground">
                  Với đà chi tiêu hiện tại, dự kiến số dư tài sản của bạn sẽ tăng thêm 5.000.000đ vào cuối tháng tới.
                </CardContent>
             </Card>
          </div>
        </div>
      </div>
    </div>
  );
}
