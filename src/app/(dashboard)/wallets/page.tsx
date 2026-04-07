"use client";

import { useState, useEffect } from "react";
import { Plus, Wallet, Pencil, Trash2, MoreVertical, CreditCard, Landmark, Banknote } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { createWallet, updateWallet, deleteWallet } from "@/app/actions/wallet-actions";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { getFormOptions } from "@/app/actions/transaction-actions";
import { formatCurrency, formatCurrencyCompact } from "@/lib/utils";

type WalletItem = {
  id: string;
  name: string;
  balance: number;
  icon?: string | null;
};

const WALLET_ICONS = [
  { name: "Wallet", icon: Wallet },
  { name: "CreditCard", icon: CreditCard },
  { name: "Landmark", icon: Landmark },
  { name: "Banknote", icon: Banknote },
];

export default function WalletsPage() {
  const [wallets, setWallets] = useState<WalletItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingWallet, setEditingWallet] = useState<WalletItem | null>(null);

  // Form State
  const [name, setName] = useState("");
  const [balance, setBalance] = useState("0");
  const [icon, setIcon] = useState("Wallet");

  const fetchWallets = async () => {
    setIsLoading(true);
    try {
      const data = await getFormOptions();
      setWallets(data.wallets.map(w => ({ ...w, balance: Number(w.balance) })));
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchWallets();
  }, []);

  const resetForm = () => {
    setName("");
    setBalance("0");
    setIcon("Wallet");
    setEditingWallet(null);
  };

  const handleOpenEdit = (wallet: WalletItem) => {
    setEditingWallet(wallet);
    setName(wallet.name);
    setBalance(wallet.balance.toString());
    setIcon(wallet.icon || "Wallet");
    setIsDialogOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name) return toast.error("Vui lòng nhập tên ví");

    const data = {
      name,
      balance: parseFloat(balance),
      icon,
    };

    let result;
    if (editingWallet) {
      result = await updateWallet(editingWallet.id, data);
    } else {
      result = await createWallet(data);
    }

    if (result.success) {
      toast.success(editingWallet ? "Cập nhật ví thành công" : "Tạo ví thành công");
      setIsDialogOpen(false);
      resetForm();
      fetchWallets();
    } else {
      toast.error(result.error);
    }
  };

  const handleDelete = async (id: string) => {
    const result = await deleteWallet(id);
    if (result.success) {
      toast.success("Xóa ví thành công");
      fetchWallets();
    } else {
      toast.error(result.error);
    }
  };

  const getIconComponent = (iconName: string) => {
    const iconObj = WALLET_ICONS.find(i => i.name === iconName);
    const IconComp = iconObj ? iconObj.icon : Wallet;
    return <IconComp className="h-5 w-5" />;
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-500">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Ví của tôi</h2>
          <p className="text-muted-foreground">Quản lý các tài khoản và nguồn tiền của bạn</p>
        </div>
        <Dialog open={isDialogOpen} onOpenChange={(open) => {
          setIsDialogOpen(open);
          if (!open) resetForm();
        }}>
          <DialogTrigger render={<Button className="rounded-full px-6 shadow-md hover:shadow-lg transition-all" />}>
            <Plus className="mr-2 h-4 w-4" /> Thêm ví mới
          </DialogTrigger>
          <DialogContent className="sm:max-w-[425px] border-none shadow-2xl glass-effect">
            <form onSubmit={handleSubmit}>
              <DialogHeader>
                <DialogTitle>{editingWallet ? "Sửa ví" : "Thêm ví mới"}</DialogTitle>
                <DialogDescription>
                  Nhập thông tin ví của bạn. Số dư này sẽ được cộng vào tổng tài sản.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-4">
                <div className="grid gap-2">
                  <Label htmlFor="name">Tên ví</Label>
                  <Input
                    id="name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="VD: Techcombank, Tiền mặt..."
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="balance">Số dư ban đầu</Label>
                  <Input
                    id="balance"
                    type="number"
                    value={balance}
                    onChange={(e) => setBalance(e.target.value)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label>Biểu tượng</Label>
                  <div className="flex gap-2">
                    {WALLET_ICONS.map((i) => (
                      <Button
                        key={i.name}
                        type="button"
                        variant={icon === i.name ? "default" : "outline"}
                        size="icon"
                        onClick={() => setIcon(i.name)}
                        className="h-10 w-10"
                      >
                        <i.icon className="h-5 w-5" />
                      </Button>
                    ))}
                  </div>
                </div>
              </div>
              <DialogFooter>
                <Button type="submit">Lưu thay đổi</Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {isLoading ? (
        <div className="grid gap-4 md:grid-cols-3 lg:grid-cols-4">
          {[1, 2, 3].map(i => (
            <Card key={i} className="h-32 animate-pulse bg-muted" />
          ))}
        </div>
      ) : wallets.length === 0 ? (
        <Card className="flex flex-col items-center justify-center p-12 text-center border-dashed border-2">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-muted">
            <Wallet className="h-8 w-8 text-muted-foreground" />
          </div>
          <h3 className="mt-4 text-lg font-semibold text-foreground">Bạn chưa có ví nào</h3>
          <p className="mb-4 mt-2 text-sm text-muted-foreground max-w-xs">
            Hãy thêm ví đầu tiên để bắt đầu quản lý các giao dịch tài chính của bạn.
          </p>
        </Card>
      ) : (
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {wallets.map((wallet) => (
            <Card key={wallet.id} className="relative overflow-hidden border-none shadow-sm hover:shadow-md transition-all group bg-card/50 backdrop-blur-sm">
              <div className="absolute top-0 left-0 w-1 h-full bg-primary" />
              <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary transition-transform group-hover:scale-110">
                    {getIconComponent(wallet.icon || "Wallet")}
                  </div>
                  <div>
                    <CardTitle className="text-base font-semibold">{wallet.name}</CardTitle>
                    <CardDescription className="text-xs">Tài khoản chính</CardDescription>
                  </div>
                </div>
                <DropdownMenu>
                  <DropdownMenuTrigger render={<Button variant="ghost" size="icon" className="h-8 w-8 rounded-full" />}>
                    <MoreVertical className="h-4 w-4" />
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end" className="glass-effect">
                    <DropdownMenuItem onClick={() => handleOpenEdit(wallet)} className="cursor-pointer">
                      <Pencil className="mr-2 h-4 w-4" /> Sửa
                    </DropdownMenuItem>
                    <AlertDialog>
                      <AlertDialogTrigger render={<DropdownMenuItem onSelect={(e) => e.preventDefault()} className="text-destructive cursor-pointer" />}>
                        <div className="flex items-center w-full">
                          <Trash2 className="mr-2 h-4 w-4" /> Xóa
                        </div>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>Bạn có chắc chắn muốn xóa?</AlertDialogTitle>
                          <AlertDialogDescription>
                            Hành động này không thể hoàn tác. Ví &quot;{wallet.name}&quot; sẽ bị xóa vĩnh viễn khỏi hệ thống.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>Hủy</AlertDialogCancel>
                          <AlertDialogAction
                            onClick={() => handleDelete(wallet.id)}
                            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                          >
                            Xóa ví
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </DropdownMenuContent>
                </DropdownMenu>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold tracking-tight text-foreground">
                  {formatCurrency(wallet.balance)}
                </div>
              </CardContent>
              <CardFooter className="pt-0 pb-4">
                <div className="text-[10px] text-muted-foreground uppercase font-medium tracking-wider">
                  Cập nhật gần đây
                </div>
              </CardFooter>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
