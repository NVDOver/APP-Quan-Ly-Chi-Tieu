"use client";

import { useState } from "react";
import { 
  deleteRecurringTransaction, 
  pauseRecurringTransaction, 
  resumeRecurringTransaction,
  triggerCronManually
} from "@/app/actions/recurring-actions";
import { RecurringTransaction, Wallet, Category } from "@prisma/client";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { format } from "date-fns";
import { toast } from "sonner";
import { PauseCircle, PlayCircle, Trash2, Repeat, Loader2 } from "lucide-react";
import { formatCurrency } from "@/lib/utils";

type RecurringWithRelations = RecurringTransaction & {
  wallet: Wallet;
  toWallet: Wallet | null;
  category: Category | null;
};

export function RecurringList({ data }: { data: RecurringWithRelations[] }) {
  const [loading, setLoading] = useState<string | null>(null);
  const [cronLoading, setCronLoading] = useState(false);

  const handleAction = async (id: string, action: 'PAUSE' | 'RESUME' | 'DELETE') => {
    setLoading(id);
    try {
      let res;
      if (action === 'PAUSE') res = await pauseRecurringTransaction(id);
      else if (action === 'RESUME') res = await resumeRecurringTransaction(id);
      else res = await deleteRecurringTransaction(id);

      if (res.success) {
        toast.success(`Đã cập nhật giao dịch`);
      } else {
        toast.error(res.error || "Có lỗi xảy ra");
      }
    } catch {
      toast.error("Lỗi khi xử lý");
    } finally {
      setLoading(null);
    }
  };

  const handleTestCron = async () => {
    setCronLoading(true);
    try {
        const res = await triggerCronManually();
        if(res.success) {
            toast.success(`Chạy Cron xong! Xử lý: ${res.data?.processedCount}, Lỗi: ${res.data?.errorsCount}`);
        } else {
            toast.error(res.error || "Có lỗi khi chạy cron");
        }
    } catch {
        toast.error("Lỗi 500 khi gọi cron");
    } finally {
        setCronLoading(false);
    }
  }

  if (data.length === 0) {
    return (
      <div className="text-center py-10 bg-card rounded-lg border border-dashed">
        <Repeat className="mx-auto h-12 w-12 text-muted-foreground opacity-50 mb-4" />
        <p className="text-muted-foreground">Chưa có giao dịch định kỳ nào.</p>
        <Button onClick={handleTestCron} variant="outline" className="mt-4" disabled={cronLoading}>
           {cronLoading ? <Loader2 className="animate-spin h-4 w-4 mr-2" /> : null}
           Chạy Cron Test Ngầm
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <Button onClick={handleTestCron} variant="secondary" size="sm" disabled={cronLoading}>
           {cronLoading ? <Loader2 className="animate-spin h-4 w-4 mr-2" /> : null}
           Chạy Cron Test (Dev Only)
        </Button>
      </div>

      {data.map((item) => (
        <Card key={item.id} className={item.status === 'PAUSED' ? 'opacity-60' : ''}>
          <CardContent className="p-4 flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <Badge variant={item.type === 'INCOME' ? 'default' : item.type === 'EXPENSE' ? 'destructive' : 'secondary'}>
                  {item.interval}
                </Badge>
                <h4 className="font-semibold">{item.note || item.category?.name || 'Chuyển tiền'}</h4>
                {item.status === 'PAUSED' && <Badge variant="outline">Đã tạm dừng</Badge>}
                {item.status === 'COMPLETED' && <Badge variant="outline" className="bg-green-100 text-green-800">Hoàn thành</Badge>}
              </div>
              <p className="text-sm text-muted-foreground">
                Ví: {item.wallet.name} {item.toWallet ? `→ ${item.toWallet.name}` : ''}
              </p>
              <p className="text-xs text-muted-foreground mt-1">
                Tiếp theo: {format(new Date(item.nextProcessingDate), "dd/MM/yyyy")}
              </p>
            </div>
            
            <div className="flex flex-col items-end gap-2">
              <span className={`font-bold ${item.type === 'INCOME' ? 'text-green-600' : item.type === 'EXPENSE' ? 'text-red-500' : ''}`}>
                {item.type === 'INCOME' ? '+' : item.type === 'EXPENSE' ? '-' : ''}{formatCurrency(Number(item.amount))}
              </span>
              <div className="flex gap-2">
                {item.status === 'ACTIVE' && (
                  <Button 
                    variant="ghost" size="icon" 
                    onClick={() => handleAction(item.id, 'PAUSE')}
                    disabled={loading === item.id}
                  >
                    {loading === item.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <PauseCircle className="h-4 w-4 text-amber-500" />}
                  </Button>
                )}
                {item.status === 'PAUSED' && (
                  <Button 
                    variant="ghost" size="icon" 
                    onClick={() => handleAction(item.id, 'RESUME')}
                    disabled={loading === item.id}
                  >
                    {loading === item.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4 text-green-500" />}
                  </Button>
                )}
                <Button 
                  variant="ghost" size="icon" 
                  onClick={() => handleAction(item.id, 'DELETE')}
                  disabled={loading === item.id}
                >
                  <Trash2 className="h-4 w-4 text-red-500" />
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
