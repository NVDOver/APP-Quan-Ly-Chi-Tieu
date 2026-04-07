import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { redirect } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ProfileForm } from "@/components/profile/profile-form";
import { PasswordForm } from "@/components/profile/password-form";
import { User, ShieldCheck, Globe, CreditCard } from "lucide-react";

export default async function ProfilePage() {
  const session = await auth();
  const userId = session!.user!.id;

  const dbUser = await prisma.user.findUnique({
    where: { id: userId },
  });


  return (
    <div className="flex flex-col space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Cài đặt Tài khoản</h2>
          <p className="text-muted-foreground mt-1 text-sm">
            Quản lý thông tin cá nhân, bảo mật và tùy chỉnh ứng dụng.
          </p>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Thông tin cá nhân & Tiền tệ */}
        <div className="space-y-6">
          <Card className="border-none shadow-sm glass-effect">
            <CardHeader className="flex flex-row items-center space-x-4 pb-2">
              <div className="p-2 rounded-xl bg-primary/10 text-primary">
                <User className="h-5 w-5" />
              </div>
              <div>
                <CardTitle className="text-lg">Thông tin hồ sơ</CardTitle>
                <CardDescription>Cập nhật tên và địa chỉ email của bạn.</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="pt-4">
              <ProfileForm user={dbUser!} />
            </CardContent>
          </Card>

          <Card className="border-none shadow-sm glass-effect">
            <CardHeader className="flex flex-row items-center space-x-4 pb-2">
              <div className="p-2 rounded-xl bg-emerald-100 text-emerald-600">
                <Globe className="h-5 w-5" />
              </div>
              <div>
                <CardTitle className="text-lg">Tiền tệ & Khu vực</CardTitle>
                <CardDescription>Chọn đơn vị tiền tệ mặc định hiển thị.</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="pt-4">
               <div className="flex items-center justify-between p-4 rounded-xl bg-muted/30 border border-muted/50">
                  <div className="flex items-center gap-3">
                    <div className="h-10 w-10 rounded-full bg-emerald-500/10 flex items-center justify-center font-bold text-emerald-600">
                      {dbUser!.currency}
                    </div>
                    <div>
                      <p className="text-sm font-bold uppercase tracking-tight">Đơn vị đang dùng</p>
                      <p className="text-xs text-muted-foreground">Tất cả số liệu sẽ được tính theo {dbUser!.currency}</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-xs font-medium text-emerald-600 bg-emerald-100 px-2 py-1 rounded-md inline-block">Mặc định</p>
                  </div>
               </div>
               <p className="mt-4 text-[11px] text-muted-foreground italic leading-relaxed">
                  * Hệ thống sẽ tự động quy đổi các giao dịch ngoại tệ sang đơn vị mặc định này dựa trên tỷ giá hiện thực.
               </p>
            </CardContent>
          </Card>
        </div>

        {/* Bảo mật & Đổi mật khẩu */}
        <div className="space-y-6">
          <Card className="border-none shadow-sm glass-effect">
            <CardHeader className="flex flex-row items-center space-x-4 pb-2">
              <div className="p-2 rounded-xl bg-rose-100 text-rose-600">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <div>
                <CardTitle className="text-lg">Bảo mật</CardTitle>
                <CardDescription>Đổi mật khẩu định kỳ để bảo vệ tài khoản.</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="pt-4">
              <PasswordForm />
            </CardContent>
          </Card>

          <Card className="border-none shadow-sm bg-primary/5 border-primary/20">
            <CardHeader className="flex flex-row items-center space-x-4 pb-2">
              <div className="p-2 rounded-xl bg-primary/10 text-primary">
                <CreditCard className="h-5 w-5" />
              </div>
              <div>
                <CardTitle className="text-lg">Gói dịch vụ</CardTitle>
                <CardDescription>Bạn đang sử dụng phiên bản Premium.</CardDescription>
              </div>
            </CardHeader>
            <CardContent className="pt-2">
               <p className="text-sm font-medium text-primary">Trạng thái: Đang hoạt động (Vĩnh viễn)</p>
               <div className="mt-4 h-1 w-full bg-primary/20 rounded-full overflow-hidden">
                  <div className="h-full bg-primary w-full animate-pulse" />
               </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
