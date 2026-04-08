"use server";

import { z } from "zod";
import prisma from "@/lib/prisma";
import { auth } from "@/lib/auth";
import { revalidatePath } from "next/cache";

const debtLoanSchema = z.object({
  type: z.enum(["DEBT", "LOAN"]),
  personName: z.string().min(1, "Vui lòng nhập tên người vay/cho vay"),
  amount: z.number().positive("Số tiền phải lớn hơn 0"),
  walletId: z.string().min(1, "Vui lòng chọn ví"),
  startDate: z.date(),
  dueDate: z.date().optional().nullable(),
  note: z.string().optional(),
});

const repaymentSchema = z.object({
  debtLoanId: z.string(),
  amount: z.number().positive("Số tiền phải lớn hơn 0"),
  date: z.date(),
  note: z.string().optional(),
});

export async function createDebtLoan(data: z.infer<typeof debtLoanSchema>) {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    const parsed = debtLoanSchema.parse(data);

    await prisma.$transaction(async (tx) => {
      // 1. Tạo bản ghi Nợ/Cho vay
      const debtLoan = await tx.debtLoan.create({
        data: {
          userId,
          walletId: parsed.walletId,
          personName: parsed.personName,
          type: parsed.type,
          amount: parsed.amount,
          remainingAmount: parsed.amount,
          startDate: parsed.startDate,
          dueDate: parsed.dueDate,
          note: parsed.note,
        },
      });

      // 2. Tạo giao dịch tài chính tương ứng
      // Nếu Vay (DEBT) -> Tiền vào ví (INCOME)
      // Nếu Cho vay (LOAN) -> Tiền ra khỏi ví (EXPENSE)
      const transactionType = parsed.type === "DEBT" ? "INCOME" : "EXPENSE";
      
      await tx.transaction.create({
        data: {
          userId,
          walletId: parsed.walletId,
          amount: parsed.amount,
          type: transactionType,
          date: parsed.startDate,
          note: `${parsed.type === "DEBT" ? "Vay từ" : "Cho mượn"} ${parsed.personName}: ${parsed.note || ""}`.trim(),
          debtLoanId: debtLoan.id,
        },
      });

      // 3. Cập nhật số dư ví
      await tx.wallet.update({
        where: { id: parsed.walletId, userId },
        data: {
          balance: transactionType === "INCOME" 
            ? { increment: parsed.amount } 
            : { decrement: parsed.amount },
        },
      });
    });

    revalidatePath("/debt-loan");
    revalidatePath("/transactions");
    revalidatePath("/");
    return { success: true };
  } catch (error) {
    console.error("Error creating debt/loan:", error);
    return { 
      success: false, 
      error: error instanceof Error ? error.message : "Đã xảy ra lỗi" 
    };
  }
}

export async function recordRepayment(data: z.infer<typeof repaymentSchema>) {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    const parsed = repaymentSchema.parse(data);

    await prisma.$transaction(async (tx) => {
      const debtLoan = await tx.debtLoan.findUnique({
        where: { id: parsed.debtLoanId, userId },
      });

      if (!debtLoan) throw new Error("Không tìm thấy bản ghi nợ/cho vay");
      if (debtLoan.status === "PAID") throw new Error("Khoản này đã được trả hết");
      
      const repaymentAmount = Number(parsed.amount);
      if (repaymentAmount > Number(debtLoan.remainingAmount)) {
        throw new Error(`Số tiền trả (${repaymentAmount}) không được lớn hơn số nợ còn lại (${debtLoan.remainingAmount})`);
      }

      // 1. Tạo giao dịch trả/thu nợ
      // Nếu đã Vay (DEBT) -> Trả nợ -> Tiền ra (EXPENSE)
      // Nếu đã Cho vay (LOAN) -> Thu nợ -> Tiền vào (INCOME)
      const transactionType = debtLoan.type === "DEBT" ? "EXPENSE" : "INCOME";

      await tx.transaction.create({
        data: {
          userId,
          walletId: debtLoan.walletId,
          amount: repaymentAmount,
          type: transactionType,
          date: parsed.date,
          note: `${debtLoan.type === "DEBT" ? "Trả nợ cho" : "Thu nợ từ"} ${debtLoan.personName}: ${parsed.note || ""}`.trim(),
          debtLoanId: debtLoan.id,
        },
      });

      // 2. Cập nhật DebtLoan
      const newRemaining = Number(debtLoan.remainingAmount) - repaymentAmount;
      await tx.debtLoan.update({
        where: { id: debtLoan.id },
        data: {
          remainingAmount: newRemaining,
          status: newRemaining <= 0 ? "PAID" : "OPEN",
        },
      });

      // 3. Cập nhật Ví
      await tx.wallet.update({
        where: { id: debtLoan.walletId, userId },
        data: {
          balance: transactionType === "INCOME" 
            ? { increment: repaymentAmount } 
            : { decrement: repaymentAmount },
        },
      });
    });

    revalidatePath("/debt-loan");
    revalidatePath("/transactions");
    revalidatePath("/");
    return { success: true };
  } catch (error) {
    console.error("Error recording repayment:", error);
    return { 
      success: false, 
      error: error instanceof Error ? error.message : "Đã xảy ra lỗi" 
    };
  }
}

export async function getDebtsLoans() {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    const data = await prisma.debtLoan.findMany({
      where: { userId },
      orderBy: { createdAt: "desc" },
      include: {
        wallet: true,
        transactions: {
            orderBy: { date: "desc" }
        }
      }
    });

    return { success: true, data };
  } catch (error) {
    return { success: false, error: "Không thể lấy dữ liệu" };
  }
}

export async function deleteDebtLoan(id: string) {
    try {
        const session = await auth();
        if (!session?.user?.id) throw new Error("Unauthorized");
        const userId = session.user.id;

        // Xoá nợ sẽ không xoá các transaction đã thực hiện để đảm bảo tính đúng đắn của lịch sử ví
        // Nếu muốn xoá sạch cả ví thì logic sẽ phức tạp hơn. Ở đây ta chỉ xoá bản ghi DebtLoan
        // và gỡ link từ Transaction
        await prisma.debtLoan.delete({
            where: { id, userId }
        });

        revalidatePath("/debt-loan");
        return { success: true };
    } catch (error) {
        return { success: false, error: "Lỗi khi xoá" };
    }
}
