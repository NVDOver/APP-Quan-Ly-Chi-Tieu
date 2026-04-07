"use client";

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { PlusCircle, Loader2 } from "lucide-react";
import { upsertBudget } from "@/app/actions/budget-actions";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { startOfMonth } from "date-fns";

const budgetSchema = z.object({
  categoryId: z.string().min(1, "Vui lòng chọn danh mục"),
  limitAmount: z.coerce.number().min(1000, "Hạn mức tối thiểu là 1.000đ"),
});

type BudgetFormValues = z.infer<typeof budgetSchema>;

interface BudgetFormProps {
  categories: { id: string; name: string }[];
}

export function BudgetForm({ categories }: BudgetFormProps) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const form = useForm<BudgetFormValues>({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    resolver: zodResolver(budgetSchema) as any,
    defaultValues: {
      categoryId: "",
      limitAmount: 0,
    },
  });

  async function onSubmit(values: BudgetFormValues) {
    setLoading(true);
    try {
      // Mặc định thiết lập cho tháng hiện tại
      const monthYear = startOfMonth(new Date());
      await upsertBudget({
        categoryId: values.categoryId,
        limitAmount: values.limitAmount,
        monthYear,
      });

      toast.success("Đã cập nhật hạn mức ngân sách!");
      setOpen(false);
      form.reset();
      router.refresh();
    } catch (error) {
      console.error(error);
      toast.error("Có lỗi xảy ra khi lưu ngân sách.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button className="shadow-lg"><PlusCircle className="mr-2 h-4 w-4" /> Thiết lập ngân sách</Button>} />
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>Ngân sách chi tiêu tháng này</DialogTitle>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4 pt-4">
            <FormField<BudgetFormValues, "categoryId">
              control={form.control}
              name="categoryId"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Danh mục chi tiêu</FormLabel>
                  <Select onValueChange={field.onChange} value={field.value}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Chọn danh mục" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {categories.map((category) => (
                        <SelectItem key={category.id} value={category.id}>
                          {category.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField<BudgetFormValues, "limitAmount">
              control={form.control}
              name="limitAmount"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Hạn mức tối đa (VND)</FormLabel>
                  <FormControl>
                    <div className="relative">
                      <Input
                        type="number"
                        placeholder="VD: 5000000"
                        className="pr-10 font-mono"
                        {...field}
                      />
                      <span className="absolute right-3 top-2.5 text-muted-foreground text-sm">₫</span>
                    </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <Button type="submit" className="w-full" disabled={loading}>
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {loading ? "Đang lưu..." : "Áp dụng hạn mức"}
            </Button>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
