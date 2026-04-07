"use client";

import { useState } from "react";
import { Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { deleteBudget } from "@/app/actions/budget-actions";
import { toast } from "sonner";
import { useRouter } from "next/navigation";

export function DeleteBudgetButton({ budgetId }: { budgetId: string }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleDelete = async () => {
    setLoading(true);
    try {
      const res = await deleteBudget(budgetId);
      if (res.success) {
        toast.success("Đã xóa ngân sách");
        setOpen(false);
        router.refresh();
      } else {
        toast.error(res.error || "Không thể xóa ngân sách");
      }
    } catch (error) {
      toast.error("Lỗi khi xóa ngân sách");
    } finally {
      setLoading(false);
    }
  };

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogTrigger>
        <div className="h-8 w-8 inline-flex items-center justify-center text-muted-foreground hover:text-rose-600 hover:bg-rose-100/50 rounded-full transition-colors cursor-pointer">
          <Trash2 className="h-4 w-4" />
        </div>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Bạn có chắc chắn muốn xóa?</AlertDialogTitle>
          <AlertDialogDescription>
            Hành động này sẽ xóa cài đặt hạn mức ngân sách của danh mục này trong tháng. Nó không ảnh hưởng đến các giao dịch đã thu/chi.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={loading}>Hủy</AlertDialogCancel>
          <AlertDialogAction onClick={handleDelete} disabled={loading} className="bg-rose-600 hover:bg-rose-700">
            {loading ? "Đang xóa..." : "Xóa ngân sách"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
