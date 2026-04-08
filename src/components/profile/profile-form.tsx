"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { updateProfile } from "@/app/actions/profile-actions";
import { toast } from "sonner";
import { Save, User, Mail, Globe } from "lucide-react";

import { useCurrency } from "@/components/currency-provider";

interface ProfileFormProps {
  user: {
    fullName: string | null;
    email: string;
    avatarUrl?: string | null;
    currency?: string;
  };
}

export function ProfileForm({ user }: ProfileFormProps) {
  const { currency, setCurrency } = useCurrency();
  const [fullName, setFullName] = useState(user.fullName || "");
  const [isPending, setIsPending] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsPending(true);
    
    try {
      const result = await updateProfile({ fullName });
      if (result.success) {
        toast.success("Cập nhật thông tin thành công!");
      } else {
        toast.error(result.error || "Có lỗi xảy ra");
      }
    } catch (error) {
      toast.error("Lỗi hệ thống");
    } finally {
      setIsPending(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="grid gap-6 md:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor="fullName" className="text-xs font-bold uppercase text-muted-foreground ml-1">Họ và tên</Label>
          <div className="relative">
            <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input 
              id="fullName" 
              value={fullName} 
              onChange={(e) => setFullName(e.target.value)} 
              placeholder="Nhập họ tên đầy đủ"
              className="pl-10 h-12 bg-muted/20 border-none rounded-2xl focus-visible:ring-primary/20"
            />
          </div>
        </div>

        <div className="space-y-2">
          <Label htmlFor="email" className="text-xs font-bold uppercase text-muted-foreground ml-1">Địa chỉ Email</Label>
          <div className="relative">
            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input 
              id="email" 
              value={user.email} 
              disabled 
              className="pl-10 h-12 bg-muted/40 border-none rounded-2xl cursor-not-allowed opacity-70"
            />
          </div>
          <p className="text-[10px] text-muted-foreground ml-1">* Email không thể thay đổi trực tiếp</p>
        </div>

        <div className="space-y-2">
          <Label className="text-xs font-bold uppercase text-muted-foreground ml-1">Đơn vị tiền tệ mặc định</Label>
          <div className="relative">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <select
              value={currency}
              onChange={(e) => setCurrency(e.target.value as "VND" | "USD")}
              className="flex h-12 w-full rounded-2xl border-none bg-muted/20 pl-10 pr-3 py-1 text-sm shadow-inner transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/20"
            >
              <option value="VND">VND - Việt Nam Đồng</option>
              <option value="USD">USD - Đô la Mỹ</option>
              <option value="EUR">EUR - Đồng Euro</option>
            </select>
          </div>
        </div>
      </div>

      <div className="flex justify-end pt-4">
        <Button 
          type="submit" 
          disabled={isPending} 
          className="rounded-full px-8 shadow-lg shadow-primary/20 hover:scale-105 transition-all"
        >
          <Save className="mr-2 h-4 w-4" /> 
          {isPending ? "Đang lưu..." : "Lưu thay đổi"}
        </Button>
      </div>
    </form>
  );
}
