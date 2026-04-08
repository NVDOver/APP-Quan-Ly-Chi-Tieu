"use client";

import { useState } from "react";
import Link from "next/link";
import { Menu, X } from "lucide-react";
import { ModeToggle } from "./mode-toggle";
import { UserNav } from "./user-nav";
import { usePathname } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";

export function Navbar() {
  const [isOpen, setIsOpen] = useState(false);
  const pathname = usePathname();

  const menuItems = [
    { name: "Tổng quan", href: "/" },
    { name: "Sổ giao dịch", href: "/transactions" },
    { name: "Ngân sách", href: "/budgets" },
    { name: "Ví của tôi", href: "/wallets" },
    { name: "Danh mục", href: "/categories" },
    { name: "Mục tiêu tiết kiệm", href: "/saving-goals" },
    { name: "Trung tâm Báo cáo", href: "/reports" },
    { name: "Cài đặt Tài khoản", href: "/profile" },
  ];

  return (
    <>
      <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto flex h-14 items-center justify-between px-4 md:px-8">
          <div className="flex items-center space-x-2">
            <button 
              className="p-2 md:hidden hover:bg-accent rounded-md transition-colors"
              onClick={() => setIsOpen(!isOpen)}
            >
              {isOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
            
            <Link href="/" className="flex items-center space-x-2 group">
              <motion.div 
                whileHover={{ scale: 1.1, rotate: 10 }}
                className="h-7 w-7 rounded-full bg-primary flex items-center justify-center shadow-lg shadow-primary/20"
              >
                <span className="text-primary-foreground font-bold text-xs">$$</span>
              </motion.div>
              <span className="font-bold sm:inline-block hidden md:block group-hover:text-primary transition-colors">
                SpendWise
              </span>
              <span className="font-bold md:hidden group-hover:text-primary transition-colors">SpendWise</span>
            </Link>
          </div>
          
          <div className="flex flex-1 items-center justify-end space-x-2 md:space-x-4">
            <nav className="flex items-center space-x-1 md:space-x-2">
              <ModeToggle />
              <UserNav />
            </nav>
          </div>
        </div>
      </header>

      <AnimatePresence>
        {/* Mobile Drawer Overlay */}
        {isOpen && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-40 bg-background/80 backdrop-blur-sm md:hidden"
            onClick={() => setIsOpen(false)}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {/* Mobile Drawer */}
        {isOpen && (
          <motion.div 
            initial={{ x: "-100%" }}
            animate={{ x: 0 }}
            exit={{ x: "-100%" }}
            transition={{ type: "spring", damping: 25, stiffness: 200 }}
            className="fixed inset-y-0 left-0 z-50 w-64 bg-card shadow-2xl md:hidden flex flex-col h-full py-6"
          >
            <div className="flex items-center justify-between px-6 mb-6">
              <span className="font-bold text-xl text-primary">SpendWise</span>
              <button 
                className="p-1 hover:bg-accent rounded-full transition-colors"
                onClick={() => setIsOpen(false)}
              >
                <X className="h-5 w-5 text-muted-foreground" />
              </button>
            </div>
            <nav className="flex-1 px-4 space-y-1">
              {menuItems.map((item, idx) => (
                <motion.div
                  key={item.href}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: idx * 0.05 }}
                >
                  <Link
                    href={item.href}
                    onClick={() => setIsOpen(false)}
                    className={`flex items-center rounded-lg px-4 py-3 font-medium transition-all ${
                      pathname === item.href 
                        ? 'bg-primary text-primary-foreground shadow-md ring-1 ring-primary/20' 
                        : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground'
                    }`}
                  >
                    {item.name}
                  </Link>
                </motion.div>
              ))}
            </nav>
            <div className="px-6 mt-auto">
               <div className="p-4 rounded-2xl bg-primary/5 border border-primary/10">
                  <p className="text-[10px] text-muted-foreground mb-1 uppercase tracking-tight font-bold">Phiên bản</p>
                  <p className="text-sm font-semibold">SpendWise App v1.2.0</p>
               </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
