import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { formatCurrency } from "@/lib/utils";
import { Wallet, CreditCard, TrendingUp, TrendingDown } from "lucide-react";
import { getDashboardMoMStats } from "@/app/actions/dashboard-actions";
import { FadeIn } from "@/components/fade-in";

export async function OverviewSection() {
  const session = await auth();
  const userId = session!.user!.id;

  const [rawWallets, momStats] = await Promise.all([
    prisma.wallet.findMany({ 
      where: { userId },
      select: { id: true, name: true, balance: true }
    }),
    getDashboardMoMStats(),
  ]);

  const wallets = rawWallets.map((w) => ({ ...w, balance: Number(w.balance) }));
  const totalBalance = wallets.reduce((acc, wallet) => acc + wallet.balance, 0);
  const walletCount = wallets.length;

  return (
    <div className="grid gap-6 md:grid-cols-3">
      <FadeIn delay={0.15} direction="up">
        <div className="premium-card relative group rounded-3xl p-6 bg-gradient-to-br from-emerald-600 to-teal-700 text-white shadow-xl shadow-emerald-500/20 overflow-hidden h-full">
          <div className="absolute -right-4 -top-4 opacity-10 group-hover:scale-110 transition-transform duration-500">
            <Wallet size={120} />
          </div>
          <p className="text-emerald-100/80 text-sm font-semibold uppercase tracking-wider mb-2">Tổng tài sản thực tế</p>
          <h3 className="text-3xl font-black mb-4 tracking-tight">{formatCurrency(totalBalance)}</h3>
          <div className="flex items-center gap-2 text-xs text-emerald-100/60 bg-white/10 w-fit px-3 py-1 rounded-full backdrop-blur-md">
            <Wallet size={12} />
            <span>{walletCount} ví đang hoạt động</span>
          </div>
        </div>
      </FadeIn>

      <FadeIn delay={0.25} direction="up">
        <div className="glass-card premium-card rounded-3xl p-6 h-full">
           <div className="flex justify-between items-start mb-4">
              <div className="p-3 bg-primary/10 rounded-2xl text-primary">
                <CreditCard size={24} />
              </div>
              <span className="text-xs font-bold text-muted-foreground uppercase">Ví & Tài khoản</span>
           </div>
           <p className="text-muted-foreground text-sm font-medium mb-1">Số lượng ví</p>
           <h3 className="text-3xl font-extrabold">{walletCount} <span className="text-lg font-normal text-muted-foreground">tài khoản</span></h3>
        </div>
      </FadeIn>

      <FadeIn delay={0.35} direction="up">
        <div className="glass-card premium-card rounded-3xl p-6 h-full border-rose-500/10">
           <div className="flex justify-between items-start mb-4">
              <div className="p-3 bg-rose-500/10 rounded-2xl text-rose-500">
                <TrendingDown size={24} />
              </div>
              <span className="text-xs font-bold text-rose-500/70 uppercase">Chi tiêu tháng</span>
           </div>
           <p className="text-muted-foreground text-sm font-medium mb-1">Tháng hiện tại</p>
           <h3 className="text-3xl font-extrabold text-rose-500">{formatCurrency(momStats.currentExpTotal || 0)}</h3>
           <div className={`mt-2 flex items-center gap-1 text-xs font-bold ${momStats.expDiffPercent >= 0 ? 'text-rose-500' : 'text-emerald-500'}`}>
              {momStats.expDiffPercent >= 0 ? <TrendingUp size={12} /> : <TrendingDown size={12} />}
              {Math.abs(momStats.expDiffPercent)}% so với tháng trước
           </div>
        </div>
      </FadeIn>
    </div>
  );
}
