"use client";

import { useEffect, useState } from "react";
import { Sparkles, TrendingUp, AlertCircle, Info, BrainCircuit } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { motion, AnimatePresence } from "framer-motion";

export function AIAdvisor() {
  const [advice, setAdvice] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchAdvice() {
      try {
        const res = await fetch("/api/ai/analyze");
        const data = await res.json();
        if (data.advice) {
          setAdvice(data.advice);
        }
      } catch (err) {
        console.error("Fetch AI advice error:", err);
      } finally {
        setLoading(false);
      }
    }
    fetchAdvice();
  }, []);

  if (loading) {
    return (
      <Card className="glass-card border-primary/20 bg-primary/5 animate-pulse rounded-3xl overflow-hidden">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-3 text-primary text-lg font-bold">
            <div className="p-2 rounded-xl bg-primary/20">
               <BrainCircuit className="h-6 w-6 animate-spin-slow" />
            </div>
            AI đang tính toán dữ liệu của bạn...
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4 pt-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="space-y-2">
               <div className="h-4 w-full rounded-full bg-muted/40" />
               <div className="h-4 w-2/3 rounded-full bg-muted/20" />
            </div>
          ))}
        </CardContent>
      </Card>
    );
  }

  // Fallback if no advice found
  const displayAdvice = advice.length > 0 ? advice : [
    "Hãy duy trì thói quen ghi chép chi tiêu hàng ngày để AI có đủ dữ liệu phân tích chuẩn xác hơn.",
    "Bạn đang quản lý tài chính khá tốt, hãy tiếp tục đặt ra các mục tiêu tiết kiệm mới nhé!",
    "Mẹo: Bạn có thể phân loại các khoản chi nhỏ vào danh mục 'Lặt vặt' để nhìn sơ đồ tổng quát rõ ràng hơn."
  ];

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.5 }}
      className="relative group h-full"
    >
      {/* Background Glow Effect */}
      <div className="absolute -inset-0.5 bg-gradient-to-r from-primary/30 to-purple-500/30 rounded-[2.2rem] blur opacity-30 group-hover:opacity-60 transition duration-1000 group-hover:duration-200"></div>
      
      <Card className="glass-card premium-card rounded-3xl overflow-hidden h-full border-primary/10 relative">
        <div className="absolute top-0 right-0 p-6 opacity-10 pointer-events-none">
            <BrainCircuit size={160} className="text-primary rotate-12" />
        </div>
        
        <CardHeader className="pb-4 relative z-10">
          <CardTitle className="flex items-center gap-3">
            <div className="p-2.5 rounded-2xl bg-primary/10 shadow-inner">
               <Sparkles className="h-6 w-6 text-emerald-500" />
            </div>
            <span className="text-gradient text-2xl font-black">AI Advisor Pro</span>
          </CardTitle>
          <div className="h-1 w-20 bg-gradient-to-r from-primary to-transparent rounded-full mt-1" />
        </CardHeader>
        
        <CardContent className="pt-2 relative z-10">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <AnimatePresence>
              {displayAdvice.map((item, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: 0.2 + index * 0.1 }}
                  className="flex flex-col gap-3 p-5 rounded-2xl bg-background/40 hover:bg-background/80 border border-border/40 hover:border-primary/30 transition-all duration-500 group/item relative overflow-hidden h-full"
                >
                  <div className={`absolute top-0 left-0 w-1 h-full ${
                     index === 0 ? "bg-emerald-500" : index === 1 ? "bg-amber-500" : "bg-blue-500"
                  }`} />
                  
                  <p className="text-sm font-semibold leading-relaxed text-foreground/80 group-hover/item:text-foreground transition-colors">
                    {item}
                  </p>
                  
                  <div className="mt-auto pt-2 flex items-center gap-2 opacity-40 group-hover/item:opacity-100 transition-opacity">
                     <div className={`p-1 rounded-md ${
                        index === 0 ? "bg-emerald-500/10 text-emerald-500" : 
                        index === 1 ? "bg-amber-500/10 text-amber-500" : 
                        "bg-blue-500/10 text-blue-500"
                     }`}>
                        {index === 0 ? <TrendingUp size={14} /> : 
                         index === 1 ? <AlertCircle size={14} /> : 
                         <Info size={14} />}
                     </div>
                     <span className="text-[10px] uppercase font-black">AI Insight {index + 1}</span>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
