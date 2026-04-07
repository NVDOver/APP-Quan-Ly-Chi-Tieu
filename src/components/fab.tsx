"use client";

import { useEffect, useState, useTransition } from "react";
import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { createTransaction, getFormOptions } from "@/app/actions/transaction-actions";
import { toast } from "sonner";

const transactionBaseSchema = z.object({
  type: z.enum(["INCOME", "EXPENSE", "TRANSFER"]),
  walletId: z.string().min(1, "Vui lòng chọn ví"),
  toWalletId: z.string().optional(),
  categoryId: z.string().optional(),
  amount: z.coerce.number().positive("Số tiền phải lớn hơn 0"),
  date: z.string().refine((val) => !isNaN(Date.parse(val)), "Ngày không hợp lệ"),
  note: z.string().optional(),
});

// Cách tiếp cận tốt hơn — dùng superRefine (1 lần, không chain):
const transactionSchema: z.ZodType<TransactionFormValues, any, any> = transactionBaseSchema.superRefine((data, ctx) => {
  if (data.type === "TRANSFER") {
    if (!data.toWalletId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Vui lòng chọn ví nhận",
        path: ["toWalletId"],
      });
    }
    if (data.walletId === data.toWalletId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Ví nguồn và ví nhận phải khác nhau",
        path: ["toWalletId"],
      });
    }
  } else {
    if (!data.categoryId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Vui lòng chọn danh mục",
        path: ["categoryId"],
      });
    }
  }
});

type OptionType = {
  id: string;
  name: string;
  type?: "INCOME" | "EXPENSE";
  balance?: number;
};

interface TransactionFormValues {
  type: "INCOME" | "EXPENSE" | "TRANSFER";
  walletId: string;
  toWalletId?: string;
  categoryId?: string;
  amount: number;
  date: string;
  note?: string;
}

export function FloatingActionButton() {
  const [open, setOpen] = useState(false);
  const [wallets, setWallets] = useState<OptionType[]>([]);
  const [categories, setCategories] = useState<OptionType[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isPending, startTransition] = useTransition();

  const form = useForm<TransactionFormValues>({
    resolver: zodResolver(transactionSchema),
    defaultValues: {
      type: "EXPENSE",
      walletId: "",
      toWalletId: "",
      categoryId: "",
      amount: 0,
      date: new Date().toISOString().split('T')[0],
      note: "",
    },
  });

  const selectedType = useWatch({
    control: form.control,
    name: "type",
    defaultValue: "EXPENSE",
  });
  const selectedWalletId = useWatch({
    control: form.control,
    name: "walletId",
  });

  useEffect(() => {
    const loadOptions = async () => {
      if (!open) return;
      setIsLoading(true);
      try {
        const data = await getFormOptions();
        setWallets(data.wallets.map((w) => ({
          id: w.id,
          name: w.name,
          balance: Number(w.balance)
        })));
        setCategories(data.categories as OptionType[]);
      } finally {
        setIsLoading(false);
      }
    };
    loadOptions();
  }, [open]);

  // Reset conditional fields logic when type changes
  useEffect(() => {
    if (selectedType === "TRANSFER") {
      form.setValue("categoryId", "");
    } else {
      form.setValue("toWalletId", "");
    }
  }, [selectedType, form]);

  function onSubmit(values: TransactionFormValues) {
    startTransition(async () => {
      const dataToSubmit = {
        ...values,
        date: new Date(values.date),
      };

      const res = await createTransaction(dataToSubmit);
      if (res.success) {
        toast.success("Tạo giao dịch thành công");
        setOpen(false);
        form.reset({
          type: "EXPENSE",
          amount: 0,
          date: new Date().toISOString().split('T')[0],
        });
      } else {
        toast.error(res.error || "Gặp lỗi khi tạo giao dịch");
      }
    });
  }

  const filteredCategories = categories.filter(c => c.type === selectedType);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button className="fixed bottom-6 right-6 h-14 w-14 rounded-full shadow-lg" size="icon" />}>
        <Plus className="h-6 w-6" />
      </DialogTrigger>
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>Thêm giao dịch mới</DialogTitle>
          <DialogDescription>
            Ghi chép một khoản thu, chi hoặc chuyển khoản.
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="py-8 text-center text-sm text-muted-foreground">Đang tải dữ liệu...</div>
        ) : (
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
              <FormField
                control={form.control}
                name="type"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Loại giao dịch</FormLabel>
                    <Select onValueChange={field.onChange} defaultValue={field.value}>
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder="Chọn loại giao dịch" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="EXPENSE">Chi tiêu</SelectItem>
                        <SelectItem value="INCOME">Thu nhập</SelectItem>
                        <SelectItem value="TRANSFER">Chuyển tiền</SelectItem>
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={form.control}
                  name="amount"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Số tiền</FormLabel>
                      <FormControl>
                        <Input type="number" placeholder="50000" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="date"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Ngày</FormLabel>
                      <FormControl>
                        <Input type="date" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <FormField
                control={form.control}
                name="walletId"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{selectedType === "TRANSFER" ? "Từ Ví" : "Ví thanh toán"}</FormLabel>
                    <Select onValueChange={field.onChange} defaultValue={field.value}>
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder="Chọn ví" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {wallets.map(w => (
                          <SelectItem key={w.id} value={w.id}>{w.name}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {selectedType === "TRANSFER" ? (
                <FormField
                  control={form.control}
                  name="toWalletId"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Đến Ví</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Chọn ví nhận" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {wallets.filter(w => w.id !== selectedWalletId).map(w => (
                            <SelectItem key={w.id} value={w.id}>{w.name}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              ) : (
                <FormField
                  control={form.control}
                  name="categoryId"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Danh mục</FormLabel>
                      <Select onValueChange={field.onChange} defaultValue={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Chọn danh mục" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {filteredCategories.map(c => (
                            <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>
                          ))}
                          {filteredCategories.length === 0 && (
                            <SelectItem value="empty" disabled>Chưa có danh mục nào</SelectItem>
                          )}
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              )}

              <FormField
                control={form.control}
                name="note"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Ghi chú</FormLabel>
                    <FormControl>
                      <Input placeholder="Ăn trưa, cà phê..." {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <Button type="submit" className="w-full" disabled={isPending}>
                {isPending ? "Đang xử lý..." : "Lưu giao dịch"}
              </Button>
            </form>
          </Form>
        )}
      </DialogContent>
    </Dialog>
  );
}
