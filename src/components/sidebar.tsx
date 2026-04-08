"use client"

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { motion } from 'framer-motion';

import { 
  LayoutDashboard, 
  ReceiptText, 
  PieChart, 
  Wallet, 
  Tags, 
  Target, 
  BarChart3, 
  Settings,
  Repeat,
  HandCoins
} from "lucide-react";

export function Sidebar() {
  const pathname = usePathname();

  const menuItems = [
    { name: "Tổng quan", href: "/", icon: LayoutDashboard },
    { name: "Sổ giao dịch", href: "/transactions", icon: ReceiptText },
    { name: "Giao dịch định kỳ", href: "/recurring-transactions", icon: Repeat },
    { name: "Ngân sách", href: "/budgets", icon: PieChart },
    { name: "Ví của tôi", href: "/wallets", icon: Wallet },
    { name: "Danh mục", href: "/categories", icon: Tags },
    { name: "Quản lý Tag", href: "/tags", icon: Tags },
    { name: "Ghi nợ & Cho vay", href: "/debt-loan", icon: HandCoins },
    { name: "Mục tiêu tiết kiệm", href: "/saving-goals", icon: Target },
    { name: "Trung tâm Báo cáo", href: "/reports", icon: BarChart3 },
    { name: "Cài đặt Tài khoản", href: "/profile", icon: Settings },
  ];

  return (
    <aside className="fixed top-14 z-30 -ml-2 hidden h-[calc(100vh-3.5rem)] w-full shrink-0 border-r md:sticky md:block md:w-64">
      <div className="h-full overflow-auto py-6 pr-6 lg:py-8 pl-6">
        <div className="flex flex-col space-y-4">
          <div className="py-2">
            <h2 className="mb-4 px-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground/70">
              Chức năng chính
            </h2>
            <div className="space-y-1">
              {menuItems.map((item) => {
                const Icon = item.icon;
                const isActive = pathname === item.href;
                
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`relative flex items-center gap-3 rounded-lg px-4 py-2.5 font-medium text-sm transition-colors duration-200 ${
                      isActive 
                        ? 'text-primary-foreground' 
                        : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                    }`}
                  >
                    {isActive && (
                      <motion.div
                        layoutId="active-nav-item"
                        className="absolute inset-0 bg-primary rounded-lg shadow-sm shadow-primary/20"
                        transition={{
                          type: "spring",
                          stiffness: 380,
                          damping: 30
                        }}
                      />
                    )}
                    <Icon className={`relative z-10 h-4 w-4 ${isActive ? 'text-primary-foreground' : 'text-muted-foreground'}`} />
                    <span className="relative z-10">{item.name}</span>
                  </Link>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}
