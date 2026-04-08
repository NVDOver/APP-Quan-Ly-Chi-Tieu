import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { User, Mail, Shield, Wallet, CreditCard, ChevronRight } from "lucide-react";
import { ProfileForm } from "@/components/profile/profile-form";
import { FadeIn } from "@/components/fade-in";

export default async function ProfilePage() {
  const session = await auth();
  const userId = session!.user!.id;

  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: {
      _count: {
        select: {
          wallets: true,
          transactions: true,
        }
      }
    }
  });

  if (!user) return null;

  return (
    <div className="flex flex-col space-y-8 pb-10">
      <FadeIn delay={0.1}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-3xl font-bold tracking-tight text-gradient">Hồ sơ cá nhân</h2>
            <p className="text-muted-foreground">Quản lý thông tin tài khoản và thiết lập cá nhân của bạn</p>
          </div>
        </div>
      </FadeIn>

      <div className="grid gap-6 md:grid-cols-3">
        <FadeIn delay={0.2} direction="left" className="md:col-span-1">
          <Card className="glass-card border-none overflow-hidden h-full">
            <div className="h-24 bg-gradient-to-r from-primary/20 to-primary/5 w-full relative">
               <div className="absolute -bottom-10 left-6">
                 <div className="h-20 w-20 rounded-3xl bg-card border-4 border-background flex items-center justify-center shadow-xl">
                   <User className="h-10 w-10 text-primary" />
                 </div>
               </div>
            </div>
            <CardHeader className="pt-14 pb-4">
              <CardTitle className="text-xl font-bold">{user.fullName || "Người dùng SpendWise"}</CardTitle>
              <CardDescription className="flex items-center gap-1">
                <Mail className="h-3 w-3" /> {user.email}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
               <div className="p-3 bg-muted/40 rounded-2xl flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-primary/10 rounded-xl">
                      <Wallet className="h-4 w-4 text-primary" />
                    </div>
                    <span className="text-sm font-medium">Số ví</span>
                  </div>
                  <span className="font-bold">{user._count.wallets}</span>
               </div>
               <div className="p-3 bg-muted/40 rounded-2xl flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-emerald-500/10 rounded-xl">
                      <CreditCard className="h-4 w-4 text-emerald-500" />
                    </div>
                    <span className="text-sm font-medium">Giao dịch</span>
                  </div>
                  <span className="font-bold">{user._count.transactions}</span>
               </div>
            </CardContent>
          </Card>
        </FadeIn>

        <FadeIn delay={0.3} direction="up" className="md:col-span-2">
          <Card className="glass-card border-none h-full">
            <CardHeader>
              <CardTitle className="text-xl font-bold">Chỉnh sửa thông tin</CardTitle>
              <CardDescription>Cập nhật họ tên và các thiết lập tài khoản</CardDescription>
            </CardHeader>
            <CardContent>
              <ProfileForm user={{ 
                fullName: user.fullName, 
                email: user.email,
                avatarUrl: user.avatarUrl,
                currency: user.currency
              }} />
            </CardContent>
          </Card>
        </FadeIn>
      </div>

      <FadeIn delay={0.4}>
         <Card className="glass-card border-none bg-primary/5">
            <CardHeader>
              <CardTitle className="text-lg font-bold">Bảo mật & Quyền riêng tư</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
               <div className="flex items-center justify-between p-4 bg-background/50 rounded-2xl border border-primary/10 hover:border-primary/30 transition-all cursor-pointer group">
                  <div className="flex items-center gap-4">
                    <div className="p-3 bg-primary/10 rounded-xl">
                      < Shield className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <p className="font-bold text-sm">Đổi mật khẩu</p>
                      <p className="text-xs text-muted-foreground">Bảo vệ tài khoản của bạn bằng mật khẩu mạnh</p>
                    </div>
                  </div>
                  <ChevronRight className="h-5 w-5 text-muted-foreground group-hover:translate-x-1 transition-transform" />
               </div>
            </CardContent>
         </Card>
      </FadeIn>
    </div>
  );
}
