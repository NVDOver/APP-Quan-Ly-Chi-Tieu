"use client";

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { Loader2, DollarSign } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
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
import { Input } from "@/components/ui/input";
import { recordRepayment } from "@/app/actions/debt-loan-actions";

const formSchema = z.object({
  amount: z.coerce.number().positive("Số tiền phải lớn hơn 0"),
  date: z.string().min(1, "Vui lòng chọn ngày"),
  note: z.string().optional(),
});

interface RepaymentFormProps {
  debtLoan: {
    id: string;
    personName: string;
    remainingAmount: string | number | object;
    type: "DEBT" | "LOAN";
  };
}

export function RepaymentForm({ debtLoan }: RepaymentFormProps) {
  const [open, setOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const form = useForm<z.infer<typeof formSchema>>({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    resolver: zodResolver(formSchema) as any,
    defaultValues: {
      amount: Number(debtLoan.remainingAmount),
      date: new Date().toISOString().split("T")[0],
      note: "",
    },
  });

  async function onSubmit(values: z.infer<typeof formSchema>) {
    setIsSubmitting(true);
    try {
      const result = await recordRepayment({
        debtLoanId: debtLoan.id,
        amount: values.amount,
        date: new Date(values.date),
        note: values.note,
      });

      if (result.success) {
        toast.success("Đã ghi nhận thanh toán");
        setOpen(false);
        form.reset();
      } else {
        toast.error(result.error || "Có lỗi xảy ra");
      }
    } catch {
      toast.error("Đã xảy ra lỗi không xác định");
    } finally {
      setIsSubmitting(false);
    }
  }

  const isDebt = debtLoan.type === "DEBT";

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger
        render={
          <Button variant="outline" className="w-full">
            <DollarSign className="mr-2 h-4 w-4" />
            {isDebt ? "Trả nợ" : "Thu nợ"}
          </Button>
        }
      />
      <DialogContent className="sm:max-w-[425px]">
        <DialogHeader>
          <DialogTitle>{isDebt ? "Trả nợ" : "Thu hồi nợ"}</DialogTitle>
          <DialogDescription>
            Ghi nhận giao dịch thanh toán cho {isDebt ? "khoản nợ từ" : "khoản cho mượn tới"} {debtLoan.personName}.
          </DialogDescription>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField<z.infer<typeof formSchema>, "amount">
              control={form.control}
              name="amount"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Số tiền thanh toán</FormLabel>
                  <FormControl>
                    <Input type="number" placeholder="0" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField<z.infer<typeof formSchema>, "date">
              control={form.control}
              name="date"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Ngày thực hiện</FormLabel>
                  <FormControl>
                    <Input type="date" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField<z.infer<typeof formSchema>, "note">
              control={form.control}
              name="note"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Ghi chú</FormLabel>
                  <FormControl>
                    <Input placeholder="Vd: Trả bớt một khoản..." {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <DialogFooter>
              <Button type="submit" disabled={isSubmitting} className="w-full">
                {isSubmitting ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Đang lưu...
                  </>
                ) : (
                  "Xác nhận thanh toán"
                )}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
