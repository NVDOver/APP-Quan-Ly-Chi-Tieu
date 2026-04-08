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
import { createRecurringTransaction } from "@/app/actions/recurring-actions";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { format } from "date-fns";

const createRecurringSchema = z.object({
  type: z.enum(["INCOME", "EXPENSE", "TRANSFER"]),
  interval: z.enum(["DAILY", "WEEKLY", "MONTHLY", "YEARLY"]),
  walletId: z.string().min(1, "Vui lòng chọn ví"),
  toWalletId: z.string().optional(),
  categoryId: z.string().optional(),
  amount: z.coerce.number().positive("Số tiền phải lớn hơn 0"),
  note: z.string().optional(),
  startDate: z.string().min(1, "Vui lòng chọn ngày bắt đầu"),
  endDate: z.string().optional(),
});

type FormValues = z.infer<typeof createRecurringSchema>;

interface RecurringFormProps {
  wallets: { id: string; name: string }[];
  categories: { id: string; name: string; type: string }[];
}

export function RecurringForm({ wallets, categories }: RecurringFormProps) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const form = useForm<FormValues>({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    resolver: zodResolver(createRecurringSchema) as any,
    defaultValues: {
      type: "EXPENSE",
      interval: "MONTHLY",
      walletId: "",
      toWalletId: "",
      categoryId: "",
      amount: 0,
      note: "",
      startDate: format(new Date(), "yyyy-MM-dd"),
      endDate: "",
    },
  });

  const watchType = form.watch("type");

  async function onSubmit(values: FormValues) {
    setLoading(true);
    try {
      const result = await createRecurringTransaction({
        ...values,
        categoryId: values.type === "TRANSFER" ? null : values.categoryId,
        toWalletId: values.type === "TRANSFER" ? values.toWalletId : null,
        startDate: new Date(values.startDate),
        endDate: values.endDate ? new Date(values.endDate) : undefined,
      });

      if (!result.success) {
        toast.error(result.error);
        return;
      }

      toast.success("Tạo giao dịch định kỳ thành công!");
      setOpen(false);
      form.reset();
      router.refresh();
    } catch (error) {
      console.error(error);
      toast.error("Có lỗi xảy ra.");
    } finally {
      setLoading(false);
    }
  }

  const filteredCategories = categories.filter((c) => c.type === watchType);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button className="shadow-lg"><PlusCircle className="mr-2 h-4 w-4" /> Thêm định kỳ mới</Button>} />
      <DialogContent className="sm:max-w-[425px] max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Tạo giao dịch định kỳ</DialogTitle>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4 pt-4">
            <FormField<FormValues, "type">
              control={form.control}
              name="type"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Loại giao dịch</FormLabel>
                    <select 
                      value={field.value}
                      className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                      onChange={(e) => field.onChange(e.target.value)}
                    >
                      <option value="EXPENSE">💸 Chi tiêu</option>
                      <option value="INCOME">💰 Thu nhập</option>
                      <option value="TRANSFER">🔄 Chuyển tiền</option>
                    </select>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div className="grid grid-cols-2 gap-4">
               <FormField<FormValues, "amount">
                  control={form.control}
                  name="amount"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Số tiền</FormLabel>
                      <FormControl>
                          <Input type="number" placeholder="0" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
               <FormField<FormValues, "interval">
                  control={form.control}
                  name="interval"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Chu kỳ lặp</FormLabel>
                      <select 
                      value={field.value}
                      className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                      onChange={(e) => field.onChange(e.target.value)}
                    >
                      <option value="DAILY">Hàng ngày</option>
                      <option value="WEEKLY">Hàng tuần</option>
                      <option value="MONTHLY">Hàng tháng</option>
                      <option value="YEARLY">Hàng năm</option>
                    </select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
            </div>

            <FormField<FormValues, "walletId">
              control={form.control}
              name="walletId"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{watchType === "TRANSFER" ? "Từ ví" : "Ví thanh toán"}</FormLabel>
                  <select 
                    value={field.value}
                    className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                    onChange={(e) => field.onChange(e.target.value)}
                  >
                    <option value="">-- Chọn ví --</option>
                    {wallets.map((w) => (
                      <option key={w.id} value={w.id}>{w.name}</option>
                    ))}
                  </select>
                  <FormMessage />
                </FormItem>
              )}
            />

            {watchType === "TRANSFER" && (
              <FormField<FormValues, "toWalletId">
                control={form.control}
                name="toWalletId"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Đến ví</FormLabel>
                    <select 
                      value={field.value}
                      className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                      onChange={(e) => field.onChange(e.target.value)}
                    >
                      <option value="">-- Chọn ví --</option>
                      {wallets.map((wallet) => (
                        <option key={wallet.id} value={wallet.id}>
                          {wallet.name}
                        </option>
                      ))}
                    </select>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}

            {watchType !== "TRANSFER" && (
              <FormField<FormValues, "categoryId">
                control={form.control}
                name="categoryId"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Danh mục</FormLabel>
                    <select 
                      value={field.value}
                      className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                      onChange={(e) => field.onChange(e.target.value)}
                    >
                      <option value="">-- Chọn danh mục --</option>
                      {filteredCategories.map((category) => (
                        <option key={category.id} value={category.id}>
                          {category.name}
                        </option>
                      ))}
                    </select>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}

            <FormField<FormValues, "note">
              control={form.control}
              name="note"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Ghi chú (Tên định kỳ)</FormLabel>
                  <FormControl>
                    <Input placeholder="VD: Lương tháng, Netflix..." {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div className="grid grid-cols-2 gap-4">
              <FormField<FormValues, "startDate">
                  control={form.control}
                  name="startDate"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Ngày bắt đầu</FormLabel>
                      <FormControl>
                          <Input type="date" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              <FormField<FormValues, "endDate">
                  control={form.control}
                  name="endDate"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Ngày kết thúc (Không bắt buộc)</FormLabel>
                      <FormControl>
                          <Input type="date" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
            </div>

            <Button type="submit" className="w-full" disabled={loading}>
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {loading ? "Đang xử lý..." : "Lưu thiết lập"}
            </Button>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
