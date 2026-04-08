"use client"

import Link from 'next/link';
import { usePathname } from 'next/navigation';

export function Sidebar() {
  const pathname = usePathname();

  const menuItems = [
    { name: "Tổng quan", href: "/" },
    { name: "Sổ giao dịch", href: "/transactions" },
    { name: "Giao dịch định kỳ", href: "/recurring-transactions" },
    { name: "Ngân sách", href: "/budgets" },
    { name: "Ví của tôi", href: "/wallets" },
    { name: "Danh mục", href: "/categories" },
    { name: "Quản lý Tag", href: "/tags" },
    { name: "Ghi nợ & Cho vay", href: "/debt-loan" },
    { name: "Mục tiêu tiết kiệm", href: "/saving-goals" },
    { name: "Trung tâm Báo cáo", href: "/reports" },
    { name: "Cài đặt Tài khoản", href: "/profile" },
  ];

  return (
    <aside className="fixed top-14 z-30 -ml-2 hidden h-[calc(100vh-3.5rem)] w-full shrink-0 border-r md:sticky md:block md:w-64">
      <div className="h-full overflow-auto py-6 pr-4 lg:py-8 pl-4 md:pl-8">
        <div className="flex flex-col space-y-4">
          <div className="px-3 py-2">
            <h2 className="mb-2 px-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Menu chính
            </h2>
            <div className="space-y-1">
              {menuItems.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`flex items-center rounded-md px-4 py-2 font-medium text-sm transition-colors ${
                    pathname === item.href 
                      ? 'bg-primary/10 text-primary font-semibold' 
                      : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                  }`}
                >
                  {item.name}
                </Link>
              ))}
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}
