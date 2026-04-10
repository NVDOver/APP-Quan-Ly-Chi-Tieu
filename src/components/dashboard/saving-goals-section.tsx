import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { formatCurrencyCompact } from "@/lib/utils";
import { Target, ArrowRight } from "lucide-react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { FadeIn } from "@/components/fade-in";

export async function SavingGoalsSection() {
  const session = await auth();
  if (!session?.user?.id) return null;
  const userId = session.user.id;

  const goals = await prisma.savingGoal.findMany({ 
    where: { userId },
    select: { id: true, name: true, targetAmount: true, currentAmount: true }
  });

  const serializedSavingGoals = goals.map((g) => ({
    ...g,
    targetAmount: Number(g.targetAmount),
    currentAmount: Number(g.currentAmount),
    percent: Math.min(Math.round((Number(g.currentAmount) / Number(g.targetAmount)) * 100), 100)
  })).sort((a, b) => b.percent - a.percent).slice(0, 3);

  return (
    <FadeIn delay={0.7} direction="up">
      <Card className="glass-card premium-card rounded-3xl h-full border-none shadow-lg">
        <CardHeader>
          <CardTitle className="text-lg font-bold">Mục tiêu Tiết kiệm</CardTitle>
          <CardDescription>Hành trình đạt được giấc mơ của bạn</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {serializedSavingGoals.length === 0 ? (
            <div className="flex flex-col items-center py-10 opacity-40">
              <Target size={40} className="mb-2" />
              <p className="text-sm">Chưa có mục tiêu nào</p>
            </div>
          ) : (
            serializedSavingGoals.map(goal => (
              <div key={goal.id} className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="font-bold truncate max-w-[200px]">{goal.name}</span>
                  <span className="text-emerald-500 font-black">{goal.percent}%</span>
                </div>
                <div className="h-3 w-full bg-muted rounded-full overflow-hidden shadow-inner">
                  <div
                    className="h-full bg-gradient-to-r from-primary to-emerald-400 rounded-full transition-all duration-1000"
                    style={{ width: `${goal.percent}%` }}
                  />
                </div>
                <div className="flex justify-between text-[10px] text-muted-foreground font-medium uppercase tracking-tighter">
                  <span>Đã tích lũy {formatCurrencyCompact(goal.currentAmount)}</span>
                  <span>Mục tiêu {formatCurrencyCompact(goal.targetAmount)}</span>
                </div>
              </div>
            ))
          )}
        </CardContent>
        {serializedSavingGoals.length > 0 && (
          <CardFooter className="pt-0 border-t border-border/10">
            <Button variant="ghost" size="sm" className="w-full mt-2 group" asChild>
              <Link href="/saving-goals" className="flex items-center justify-center">
                Xem tất cả kế hoạch <ArrowRight className="ml-2 h-4 w-4 transition-transform group-hover:translate-x-1" />
              </Link>
            </Button>
          </CardFooter>
        )}
      </Card>
    </FadeIn>
  );
}
