import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { formatCurrency } from "@/lib/utils";
import { Wallet, PlusCircle, TrendingUp, TrendingDown } from "lucide-react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { FadeIn } from "@/components/fade-in";

export async function WalletsAndCategoriesSection() {
  const session = await auth();
  if (!session?.user?.id) return null;
  const userId = session.user.id;

  const [walletsRaw, categories] = await Promise.all([
    prisma.wallet.findMany({ 
      where: { userId },
      select: { id: true, name: true, balance: true }
    }),
    prisma.category.findMany({ 
      where: { userId, isDeleted: false },
      select: { id: true, name: true, type: true },
      take: 4
    })
  ]);

  const wallets = walletsRaw.map(w => ({ ...w, balance: Number(w.balance) })).slice(0, 4);

  return (
    <div className="grid gap-6 md:grid-cols-2">
      {/* Wallet List Card */}
      <FadeIn delay={0.75} direction="up">
        <Card className="glass-card premium-card rounded-3xl border-none shadow-lg">
          <CardHeader className="flex flex-row items-center justify-between">
            <div>
              <CardTitle className="text-lg font-bold">Danh sách Ví</CardTitle>
              <CardDescription>Quản lý các nguồn tiền</CardDescription>
            </div>
            <Button variant="outline" size="icon" className="rounded-xl" asChild>
              <Link href="/wallets"><PlusCircle className="h-4 w-4" /></Link>
            </Button>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {wallets.length === 0 ? (
                <div className="text-center py-6 text-muted-foreground italic">Trống</div>
              ) : (
                wallets.map((wallet) => (
                  <div key={wallet.id} className="group flex items-center p-3 rounded-2xl hover:bg-accent/50 transition-colors">
                    <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-primary/10 text-primary shadow-inner">
                      <Wallet className="h-6 w-6" />
                    </div>
                    <div className="ml-4 flex-1 overflow-hidden">
                      <p className="text-sm font-bold truncate tracking-tight">{wallet.name}</p>
                      <p className="text-[10px] text-muted-foreground uppercase font-medium">Hoạt động</p>
                    </div>
                    <div className="text-right">
                       <p className="text-sm font-black text-primary">{formatCurrency(wallet.balance)}</p>
                       <div className="h-1 w-12 bg-primary/20 rounded-full ml-auto mt-1" />
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </FadeIn>

      {/* Recent Categories/Activity */}
      <FadeIn delay={0.8} direction="up">
        <Card className="glass-card premium-card rounded-3xl border-none shadow-lg">
          <CardHeader>
            <CardTitle className="text-lg font-bold">Phân loại Dòng tiền</CardTitle>
            <CardDescription>Các danh mục giao dịch</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {categories.length === 0 ? (
                <div className="text-center py-6 text-muted-foreground italic">Trống</div>
              ) : (
                categories.map((category) => (
                  <div key={category.id} className="flex items-center p-3 rounded-2xl hover:bg-accent/50 transition-colors">
                    <div className={`flex h-12 w-12 items-center justify-center rounded-2xl shadow-inner ${
                      category.type === 'INCOME' 
                        ? 'bg-emerald-500/10 text-emerald-500' 
                        : 'bg-rose-500/10 text-rose-500'
                    }`}>
                      {category.type === 'INCOME' ? <TrendingUp size={24} /> : <TrendingDown size={24} />}
                    </div>
                    <div className="ml-4 flex-1">
                      <p className="text-sm font-bold">{category.name}</p>
                      <p className="text-[10px] text-muted-foreground uppercase font-medium">
                        {category.type === 'INCOME' ? 'Thu nhập' : 'Chi tiêu'}
                      </p>
                    </div>
                    <div className="p-2">
                       <div className={`h-2 w-2 rounded-full ${category.type === 'INCOME' ? 'bg-emerald-500' : 'bg-rose-500'} animate-pulse`} />
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </FadeIn>
    </div>
  );
}
