"use client";

import { useState, useEffect } from "react";
import { 
  Plus, 
  Pencil, 
  Trash2, 
  Search,
  ShoppingCart, 
  Utensils, 
  Car, 
  Home, 
  Zap, 
  Heart, 
  Gift, 
  Briefcase, 
  TrendingUp, 
  Settings,
  Check
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { createCategory, updateCategory, deleteCategory, getCategories } from "@/app/actions/category-actions";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";

type CategoryItem = {
  id: string;
  name: string;
  type: "INCOME" | "EXPENSE";
  icon?: string | null;
  color?: string | null;
};

const CATEGORY_ICONS = [
  { name: "ShoppingCart", icon: ShoppingCart },
  { name: "Utensils", icon: Utensils },
  { name: "Car", icon: Car },
  { name: "Home", icon: Home },
  { name: "Zap", icon: Zap },
  { name: "Heart", icon: Heart },
  { name: "Gift", icon: Gift },
  { name: "Briefcase", icon: Briefcase },
  { name: "TrendingUp", icon: TrendingUp },
  { name: "Settings", icon: Settings },
];

const PRESET_COLORS = [
  "#ef4444", "#f97316", "#f59e0b", "#10b981", 
  "#3b82f6", "#6366f1", "#8b5cf6", "#d946ef", 
  "#ec4899", "#64748b"
];

import { FadeIn } from "@/components/fade-in";

export default function CategoriesPage() {
  const [categories, setCategories] = useState<CategoryItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingCategory, setEditingCategory] = useState<CategoryItem | null>(null);
  const [searchQuery, setSearchQuery] = useState("");

  // Form State
  const [name, setName] = useState("");
  const [type, setType] = useState<"INCOME" | "EXPENSE">("EXPENSE");
  const [icon, setIcon] = useState("ShoppingCart");
  const [color, setColor] = useState("#3b82f6");

  const fetchCategories = async () => {
    setIsLoading(true);
    try {
      const data = await getCategories();
      setCategories(data as CategoryItem[]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchCategories();
  }, []);

  const resetForm = () => {
    setName("");
    setType("EXPENSE");
    setIcon("ShoppingCart");
    setColor("#3b82f6");
    setEditingCategory(null);
  };

  const handleOpenEdit = (category: CategoryItem) => {
    setEditingCategory(category);
    setName(category.name);
    setType(category.type);
    setIcon(category.icon || "ShoppingCart");
    setColor(category.color || "#3b82f6");
    setIsDialogOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name) return toast.error("Vui lòng nhập tên danh mục");

    const data = { name, type, icon, color };

    let result;
    if (editingCategory) {
      result = await updateCategory(editingCategory.id, data);
    } else {
      result = await createCategory(data);
    }

    if (result.success) {
      toast.success(editingCategory ? "Cập nhật thành công" : "Tạo danh mục thành công");
      setIsDialogOpen(false);
      resetForm();
      fetchCategories();
    } else {
      toast.error(result.error);
    }
  };

  const handleDelete = async (id: string) => {
    const result = await deleteCategory(id);
    if (result.success) {
      toast.success("Xóa danh mục thành công (Soft Delete)");
      fetchCategories();
    } else {
      toast.error(result.error);
    }
  };

  const getIconComponent = (iconName: string, iconColor?: string | null) => {
    const iconObj = CATEGORY_ICONS.find(i => i.name === iconName);
    const IconComp = iconObj ? iconObj.icon : ShoppingCart;
    return <IconComp className="h-4 w-4" style={{ color: iconColor || "currentColor" }} />;
  };

  const filteredCategories = categories.filter(c => 
    c.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const renderCategoryTable = (items: CategoryItem[]) => (
    <div className="rounded-2xl border bg-card/50 backdrop-blur-sm overflow-hidden shadow-sm">
      <Table>
        <TableHeader className="bg-muted/30">
          <TableRow className="hover:bg-transparent">
            <TableHead className="w-[300px] font-bold">Tên danh mục</TableHead>
            <TableHead className="font-bold">Biểu tượng & Màu sắc</TableHead>
            <TableHead className="text-right font-bold">Thao tác</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 ? (
            <TableRow>
              <TableCell colSpan={3} className="text-center py-12 text-muted-foreground italic">
                Không tìm thấy danh mục nào.
              </TableCell>
            </TableRow>
          ) : (
            items.map((category) => (
              <TableRow key={category.id} className="group hover:bg-primary/5 transition-colors">
                <TableCell className="font-bold">
                  <div className="flex items-center gap-3">
                    <div 
                      className="h-10 w-10 rounded-2xl flex items-center justify-center bg-muted/50 transition-transform group-hover:scale-110"
                      style={{ border: `2px solid ${category.color || '#ddd'}` }}
                    >
                      {getIconComponent(category.icon || "ShoppingCart", category.color)}
                    </div>
                    {category.name}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className="text-[10px] uppercase tracking-widest px-2 font-bold opacity-70">
                      {category.icon || "Default"}
                    </Badge>
                    <div 
                      className="h-4 w-4 rounded-full shadow-sm" 
                      style={{ backgroundColor: category.color || '#ddd' }} 
                    />
                  </div>
                </TableCell>
                <TableCell className="text-right">
                  <div className="flex justify-end gap-2 opacity-0 group-hover:opacity-100 transition-all">
                    <Button variant="ghost" size="icon" className="h-8 w-8 rounded-full hover:bg-primary/10 hover:text-primary" onClick={() => handleOpenEdit(category)}>
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <AlertDialog>
                      <AlertDialogTrigger render={<Button variant="ghost" size="icon" className="h-8 w-8 rounded-full hover:bg-destructive/10 hover:text-destructive" />}>
                        <Trash2 className="h-4 w-4" />
                      </AlertDialogTrigger>
                      <AlertDialogContent className="glass-effect border-none shadow-2xl rounded-3xl">
                        <AlertDialogHeader>
                          <AlertDialogTitle>Xác nhận xóa danh mục?</AlertDialogTitle>
                          <AlertDialogDescription>
                            Danh mục &quot;{category.name}&quot; sẽ được đánh dấu là đã xóa. Các giao dịch cũ vẫn sẽ giữ lại danh mục này.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel className="rounded-xl">Hủy</AlertDialogCancel>
                          <AlertDialogAction 
                            onClick={() => handleDelete(category.id)}
                            className="bg-destructive text-destructive-foreground hover:bg-destructive/90 rounded-xl"
                          >
                            Xóa
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </div>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );

  return (
    <div className="space-y-8 pb-10">
      <FadeIn delay={0.1}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-3xl font-bold tracking-tight text-gradient">Danh mục phân loại</h2>
            <p className="text-muted-foreground">Tổ chức các khoản chi tiêu và thu nhập của bạn</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="relative w-full md:w-64">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input 
                placeholder="Tìm kiếm danh mục..." 
                className="pl-9 bg-card/50 rounded-xl" 
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <Dialog open={isDialogOpen} onOpenChange={(open) => {
              setIsDialogOpen(open);
              if (!open) resetForm();
            }}>
              <DialogTrigger render={<Button className="rounded-full shadow-lg shadow-primary/10 hover:scale-105 transition-all px-6" />}>
                <Plus className="mr-2 h-4 w-4" /> Thêm danh mục
              </DialogTrigger>
            <DialogContent className="sm:max-w-[425px] glass-effect border-none shadow-2xl">
              <form onSubmit={handleSubmit}>
                <DialogHeader>
                  <DialogTitle>{editingCategory ? "Sửa danh mục" : "Tạo danh mục mới"}</DialogTitle>
                </DialogHeader>
                <div className="grid gap-6 py-6">
                  <div className="grid gap-2">
                    <Label htmlFor="cat-name">Tên danh mục</Label>
                    <Input 
                      id="cat-name" 
                      value={name} 
                      onChange={(e) => setName(e.target.value)} 
                      placeholder="VD: Ăn uống, Lương..." 
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label>Loại</Label>
                    <Tabs value={type} onValueChange={(v) => setType(v as "INCOME" | "EXPENSE")} className="w-full">
                      <TabsList className="grid w-full grid-cols-2">
                        <TabsTrigger value="EXPENSE">Chi tiêu</TabsTrigger>
                        <TabsTrigger value="INCOME">Thu nhập</TabsTrigger>
                      </TabsList>
                    </Tabs>
                  </div>
                  <div className="grid gap-2">
                    <Label>Biểu tượng</Label>
                    <div className="grid grid-cols-5 gap-2">
                      {CATEGORY_ICONS.map((i) => (
                        <Button
                          key={i.name}
                          type="button"
                          variant={icon === i.name ? "default" : "outline"}
                          size="icon"
                          onClick={() => setIcon(i.name)}
                          className="h-10 w-10 transition-all hover:scale-110"
                        >
                          <i.icon className="h-5 w-5" />
                        </Button>
                      ))}
                    </div>
                  </div>
                  <div className="grid gap-2">
                    <Label>Màu sắc thương hiệu</Label>
                    <div className="flex flex-wrap gap-3">
                      {PRESET_COLORS.map((c) => (
                        <button
                          key={c}
                          type="button"
                          className={`h-8 w-8 rounded-full border-2 transition-all hover:scale-125 ${color === c ? 'border-primary scale-110 shadow-md' : 'border-transparent'}`}
                          style={{ backgroundColor: c }}
                          onClick={() => setColor(c)}
                        >
                          {color === c && <Check className="h-4 w-4 mx-auto text-white drop-shadow-sm" />}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
                <DialogFooter>
                  <Button type="submit" className="w-full">Lưu danh mục</Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>
        </div>
      </div>
    </FadeIn>

      <Tabs defaultValue="EXPENSE" className="w-full">
        <TabsList className="bg-muted/50 border mb-6">
          <TabsTrigger value="EXPENSE" className="px-8">Khoản chi tiêu</TabsTrigger>
          <TabsTrigger value="INCOME" className="px-8">Khoản thu nhập</TabsTrigger>
        </TabsList>
        
        {isLoading ? (
          <div className="space-y-4">
            {[1, 2, 3].map(i => <div key={i} className="h-12 w-full animate-pulse bg-muted rounded-md" />)}
          </div>
        ) : (
          <>
            <TabsContent value="EXPENSE">
              {renderCategoryTable(filteredCategories.filter(c => c.type === "EXPENSE"))}
            </TabsContent>
            <TabsContent value="INCOME">
              {renderCategoryTable(filteredCategories.filter(c => c.type === "INCOME"))}
            </TabsContent>
          </>
        )}
      </Tabs>
    </div>
  );
}
