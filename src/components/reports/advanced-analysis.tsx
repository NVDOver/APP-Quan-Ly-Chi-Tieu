"use client";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { TrendingUp, TrendingDown, ArrowUpRight, ArrowDownRight, Target, Info } from "lucide-react";
import { formatCurrency } from "@/lib/utils";

interface AdvancedAnalysisProps {
  stats: any;
}

export function AdvancedAnalysis({ stats }: AdvancedAnalysisProps) {
  const { currentExpTotal, prevExpTotal, expDiffPercent } = stats;
  const isUp = expDiffPercent >= 0;

  // Giẻ định: Dự báo (Forecasting) bằng trung bình 3 tháng gần nhất
  // Ở đây chúng ta chỉ có current và prev, nên lấy trung bình 2 tháng
  const forecast = Math.round((currentExpTotal + prevExpTotal) / 2);

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <Card className="glass-card border-none shadow-sm h-full group hover:shadow-xl transition-all duration-500 overflow-hidden">
        <div className={`h-1.5 w-full ${isUp ? 'bg-rose-500' : 'bg-emerald-500'}`} />
        <CardHeader className="pb-2">
          <CardTitle className="text-lg font-bold flex items-center justify-between">
            So sánh hằng tháng
            <div className={`p-2 rounded-xl scale-75 ${isUp ? 'bg-rose-500/10 text-rose-500' : 'bg-emerald-500/10 text-emerald-500'}`}>
              {isUp ? <ArrowUpRight className="h-6 w-6" /> : <ArrowDownRight className="h-6 w-6" />}
            </div>
          </CardTitle>
          <CardDescription>Biến động chi tiêu so với tháng trước</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
           <div className="flex items-end gap-2">
              <h3 className={`text-4xl font-black tracking-tight ${isUp ? 'text-rose-600' : 'text-emerald-500'}`}>
                {Math.abs(expDiffPercent)}%
              </h3>
              <span className="text-muted-foreground text-sm font-bold mb-1 uppercase tracking-widest">
                {isUp ? "Tăng trưởng" : "Giảm thiểu"}
              </span>
           </div>

           <div className="space-y-3">
              <div className="flex justify-between text-xs font-bold uppercase tracking-tighter">
                <span className="text-muted-foreground">Tháng {new Date().getMonth() || 12}</span>
                <span>{formatCurrency(prevExpTotal)}</span>
              </div>
              <div className="h-2 w-full bg-muted rounded-full overflow-hidden shadow-inner flex">
                 <div 
                   className="h-full bg-muted-foreground/30 transition-all duration-1000" 
                   style={{ width: `${prevExpTotal > currentExpTotal ? 100 : (prevExpTotal/currentExpTotal)*100}%` }}
                 />
              </div>
              
              <div className="flex justify-between text-xs font-black uppercase tracking-tighter mt-4">
                <span className="text-primary">Tháng Hiện Tại</span>
                <span className="text-primary">{formatCurrency(currentExpTotal)}</span>
              </div>
              <div className="h-3 w-full bg-muted rounded-full overflow-hidden shadow-inner flex">
                 <div 
                   className={`h-full opacity-80 rounded-full transition-all duration-1000 ${isUp ? 'bg-rose-500' : 'bg-emerald-500'}`} 
                   style={{ width: `${currentExpTotal > prevExpTotal ? 100 : (currentExpTotal/prevExpTotal)*100}%` }}
                 />
              </div>
           </div>
        </CardContent>
      </Card>

      <Card className="glass-card border-none shadow-sm h-full group hover:shadow-xl transition-all duration-500 overflow-hidden bg-primary/5">
        <div className="h-1.5 w-full bg-primary" />
        <CardHeader className="pb-2">
          <CardTitle className="text-lg font-bold flex items-center justify-between">
            Dự báo chi tiêu
            <div className="p-2 rounded-xl scale-75 bg-primary/10 text-primary">
              <TrendingUp className="h-6 w-6" />
            </div>
          </CardTitle>
          <CardDescription>Ước tính dựa trên lịch sử 60 ngày</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
           <div className="p-6 bg-background/50 rounded-3xl border border-primary/10 text-center relative overflow-hidden group-hover:scale-105 transition-transform">
              <p className="text-xs text-muted-foreground font-black uppercase tracking-widest mb-2">Số tiền dự báo tháng tới</p>
              <h3 className="text-3xl font-black text-primary tracking-tight">{formatCurrency(forecast)}</h3>
              <div className="absolute -right-2 -bottom-2 opacity-10 group-hover:rotate-12 transition-transform">
                <Target size={80} />
              </div>
           </div>

           <div className="flex items-start gap-3 p-4 bg-primary/5 rounded-2xl text-[11px] border border-primary/10">
              <Info className="h-4 w-4 text-primary shrink-0" />
              <p className="font-bold leading-relaxed text-muted-foreground">
                Hệ thống AI phân tích thấy chu kỳ chi tiêu của bạn có xu hướng {isUp ? "tăng dần" : "ổn định"}. 
                {isUp ? " Hãy cân nhắc cắt giảm các khoản không cần thiết." : " Duy trì phong độ này để sớm đạt mục tiêu tiết kiệm!"}
              </p>
           </div>
        </CardContent>
      </Card>
    </div>
  );
}
