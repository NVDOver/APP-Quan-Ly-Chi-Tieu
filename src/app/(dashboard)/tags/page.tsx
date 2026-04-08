"use client";

import { useState, useEffect } from "react";
import { 
  Plus, 
  Pencil, 
  Trash2, 
  Search,
  Tag as TagIcon,
  Check,
  Hash
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { createTag, updateTag, deleteTag, getTags } from "@/app/actions/tag-actions";
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
import { Badge } from "@/components/ui/badge";

type TagItem = {
  id: string;
  name: string;
  color?: string | null;
  _count?: {
    transactions: number;
  };
};

const PRESET_COLORS = [
  "#ef4444", "#f97316", "#f59e0b", "#84cc16",
  "#22c55e", "#14b8a6", "#06b6d4", "#3b82f6",
  "#6366f1", "#8b5cf6", "#a855f7", "#ec4899",
];

export default function TagsPage() {
  const [tags, setTags] = useState<TagItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingTag, setEditingTag] = useState<TagItem | null>(null);
  const [searchQuery, setSearchQuery] = useState("");

  // Form State
  const [name, setName] = useState("");
  const [color, setColor] = useState("#3b82f6");

  const fetchTags = async () => {
    setIsLoading(true);
    try {
      const res = await getTags();
      if (res.success) {
        setTags(res.data as TagItem[]);
      }
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchTags();
  }, []);

  const resetForm = () => {
    setName("");
    setColor("#3b82f6");
    setEditingTag(null);
  };

  const handleOpenEdit = (tag: TagItem) => {
    setEditingTag(tag);
    setName(tag.name);
    setColor(tag.color || "#3b82f6");
    setIsDialogOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name) return toast.error("Vui lòng nhập tên tag");

    const data = { name, color };

    let result;
    if (editingTag) {
      result = await updateTag(editingTag.id, data);
    } else {
      result = await createTag(data);
    }

    if (result.success) {
      toast.success(editingTag ? "Cập nhật thành công" : "Tạo tag thành công");
      setIsDialogOpen(false);
      resetForm();
      fetchTags();
    } else {
      toast.error(result.error || "Có lỗi xảy ra");
    }
  };

  const handleDelete = async (id: string) => {
    const result = await deleteTag(id);
    if (result.success) {
      toast.success("Xóa tag thành công");
      fetchTags();
    } else {
      toast.error(result.error || "Có lỗi xảy ra");
    }
  };

  const filteredTags = tags.filter(t => 
    t.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-8 animate-in fade-in duration-700">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <Hash className="h-8 w-8 text-primary" />
            Quản lý Thẻ (Tags)
          </h2>
          <p className="text-muted-foreground">Phân loại chi tiết và gắn nhãn cho các giao dịch của bạn</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="relative w-full md:w-64">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input 
              placeholder="Tìm kiếm tag..." 
              className="pl-9 bg-card/50" 
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          <Dialog open={isDialogOpen} onOpenChange={(open) => {
            setIsDialogOpen(open);
            if (!open) resetForm();
          }}>
            <DialogTrigger render={<Button className="rounded-full shadow-lg" />}>
              <Plus className="mr-2 h-4 w-4" /> Thêm Tag
            </DialogTrigger>
            <DialogContent className="sm:max-w-[425px] glass-effect border-none shadow-2xl">
              <form onSubmit={handleSubmit}>
                <DialogHeader>
                  <DialogTitle>{editingTag ? "Sửa Tag" : "Tạo Tag mới"}</DialogTitle>
                </DialogHeader>
                <div className="grid gap-6 py-6">
                  <div className="grid gap-2">
                    <Label htmlFor="tag-name">Tên Tag</Label>
                    <div className="relative">
                      <Hash className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                      <Input 
                        id="tag-name" 
                        value={name} 
                        onChange={(e) => setName(e.target.value)} 
                        placeholder="VD: hanoi-trip, ban-be..." 
                        className="pl-9"
                      />
                    </div>
                  </div>
                  
                  <div className="grid gap-2">
                    <Label>Màu sắc</Label>
                    <div className="flex flex-wrap gap-3">
                      {PRESET_COLORS.map((c) => (
                        <button
                          key={c}
                          type="button"
                          className={`h-8 w-8 rounded-full border-2 transition-all hover:scale-125 flex items-center justify-center ${color === c ? 'border-primary scale-110 shadow-md' : 'border-transparent'}`}
                          style={{ backgroundColor: c }}
                          onClick={() => setColor(c)}
                        >
                          {color === c && <Check className="h-4 w-4 text-white drop-shadow-sm" />}
                        </button>
                      ))}
                    </div>
                  </div>
                  
                  <div className="p-4 border rounded-lg bg-muted/30 flex items-center justify-center">
                    <Badge 
                      style={{ 
                        backgroundColor: `${color}20`, 
                        color: color,
                        borderColor: color
                      }}
                      className="text-lg px-4 py-1 border"
                    >
                      # {name || "preview"}
                    </Badge>
                  </div>
                </div>
                <DialogFooter>
                  <Button type="submit" className="w-full">Lưu Tag</Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      <div className="rounded-xl border bg-card shadow-sm overflow-hidden">
        <Table>
          <TableHeader className="bg-muted/50">
            <TableRow>
              <TableHead className="w-[300px]">Tên thẻ</TableHead>
              <TableHead>Màu sắc</TableHead>
              <TableHead className="text-center">Số giao dịch</TableHead>
              <TableHead className="text-right">Thao tác</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              [1, 2, 3].map(i => (
                <TableRow key={i}>
                  <TableCell colSpan={4}><div className="h-10 w-full animate-pulse bg-muted rounded" /></TableCell>
                </TableRow>
              ))
            ) : filteredTags.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} className="text-center py-12 text-muted-foreground">
                  <div className="flex flex-col items-center gap-2">
                    <TagIcon className="h-8 w-8 opacity-20" />
                    <p>Không tìm thấy thẻ nào.</p>
                  </div>
                </TableCell>
              </TableRow>
            ) : (
              filteredTags.map((tag) => (
                <TableRow key={tag.id} className="group">
                  <TableCell>
                    <Badge 
                      variant="secondary" 
                      className="px-3 py-1 font-medium"
                      style={{ 
                        backgroundColor: `${tag.color}15`, 
                        color: tag.color || undefined,
                        borderColor: tag.color || undefined
                      }}
                    >
                      # {tag.name}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                       <div className="h-4 w-4 rounded-full" style={{ backgroundColor: tag.color || '#ccc' }} />
                       <span className="text-xs font-mono text-muted-foreground uppercase">{tag.color}</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-center font-semibold">
                    {tag._count?.transactions || 0}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                      <Button variant="ghost" size="icon" onClick={() => handleOpenEdit(tag)}>
                        <Pencil className="h-4 w-4 text-muted-foreground hover:text-foreground" />
                      </Button>
                      <AlertDialog>
                        <AlertDialogTrigger render={<Button variant="ghost" size="icon" />}>
                          <Trash2 className="h-4 w-4 text-muted-foreground hover:text-destructive" />
                        </AlertDialogTrigger>
                        <AlertDialogContent className="glass-effect border-none">
                          <AlertDialogHeader>
                            <AlertDialogTitle>Xác nhận xóa Tag?</AlertDialogTitle>
                            <AlertDialogDescription>
                              Xóa thẻ &quot;#{tag.name}&quot; sẽ gỡ bỏ nhãn này khỏi tất cả các giao dịch liên quan. Hành động này không thể hoàn tác.
                            </AlertDialogDescription>
                          </AlertDialogHeader>
                          <AlertDialogFooter>
                            <AlertDialogCancel>Hủy</AlertDialogCancel>
                            <AlertDialogAction 
                              onClick={() => handleDelete(tag.id)}
                              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
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
    </div>
  );
}
