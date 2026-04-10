import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { syncNotificationsForAllUsers } from "@/lib/notification-service";

function calculateNextDate(currentDate: Date, interval: "DAILY" | "WEEKLY" | "MONTHLY" | "YEARLY"): Date {
    const next = new Date(currentDate);
    switch (interval) {
        case "DAILY":
            next.setDate(next.getDate() + 1);
            break;
        case "WEEKLY":
            next.setDate(next.getDate() + 7);
            break;
        case "MONTHLY":
            next.setMonth(next.getMonth() + 1);
            break;
        case "YEARLY":
            next.setFullYear(next.getFullYear() + 1);
            break;
    }
    return next;
}

export async function GET(request: Request) {
    try {
        // Auth check bằng token
        const authHeader = request.headers.get("authorization");
        const cronSecret = process.env.CRON_SECRET || 'dev_secret';
        if (authHeader !== `Bearer ${cronSecret}`) {
            return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
        }

        const now = new Date();

        // 1. Lấy tất cả recurring transactions đến hạn
        const dueTransactions = await prisma.recurringTransaction.findMany({
            where: {
                status: "ACTIVE",
                nextProcessingDate: {
                    lte: now
                }
            }
        });

        let processedCount = 0;
        let errorsCount = 0;

        // 2. Xử lý từng transaction một
        for (const recurring of dueTransactions) {
            try {
                await prisma.$transaction(async (tx) => {
                    // Update số dư ví
                    if (recurring.type === "TRANSFER") {
                        if (!recurring.toWalletId) throw new Error("Chuyển tiền thiếu ví nhận");
                        await tx.wallet.update({
                            where: { id: recurring.walletId },
                            data: { balance: { decrement: recurring.amount } }
                        });
                        await tx.wallet.update({
                            where: { id: recurring.toWalletId },
                            data: { balance: { increment: recurring.amount } }
                        });
                    } else {
                        await tx.wallet.update({
                            where: { id: recurring.walletId },
                            data: {
                                balance: recurring.type === "INCOME"
                                    ? { increment: recurring.amount }
                                    : { decrement: recurring.amount }
                            }
                        });
                    }

                    // Sinh giao dịch mới (với date là nextProcessingDate lúc trước)
                    await tx.transaction.create({
                        data: {
                            userId: recurring.userId,
                            walletId: recurring.walletId,
                            toWalletId: recurring.toWalletId,
                            categoryId: recurring.categoryId,
                            type: recurring.type,
                            amount: recurring.amount,
                            note: recurring.note ? `[Định kỳ] ${recurring.note}` : "[Giao dịch định kỳ tự động]",
                            date: recurring.nextProcessingDate,
                            recurringTransactionId: recurring.id
                        }
                    });

                    // Cập nhật ngày kế tiếp
                    let nextDate = calculateNextDate(recurring.nextProcessingDate, recurring.interval);
                    
                    // Nếu nextDate vẫn <= now (trường hợp bị lỡ nhiều kỳ do server chết),
                    // Có thể chúng ta nên xử lý vòng lặp nhưng để an toàn chống loop lặp vô hạn thì nhảy tới tương lai gần nhất
                    while (nextDate <= now) {
                         nextDate = calculateNextDate(nextDate, recurring.interval);
                    }

                    let newStatus = recurring.status;
                    if (recurring.endDate && nextDate > recurring.endDate) {
                        newStatus = "COMPLETED";
                    }

                    await tx.recurringTransaction.update({
                        where: { id: recurring.id },
                        data: {
                            lastProcessedDate: now,
                            nextProcessingDate: nextDate,
                            status: newStatus
                        }
                    });
                });
                processedCount++;
            } catch (err) {
                console.error(`Failed to process recurring transaction ${recurring.id}`, err);
                errorsCount++;
            }
        }

        const notificationSync = await syncNotificationsForAllUsers();

        return NextResponse.json({
            success: true,
            processedCount,
            errorsCount,
            notificationUsers: notificationSync.processedUsers,
            notificationsCreated: notificationSync.createdCount,
            timestamp: now.toISOString()
        });
    } catch (error) {
        console.error("Cron Error:", error);
        return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
    }
}
