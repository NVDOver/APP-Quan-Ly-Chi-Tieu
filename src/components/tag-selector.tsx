"use client";

import { useState, useEffect } from "react";
import { Plus, Check, X, Tag as TagIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { createTag } from "@/app/actions/tag-actions";
import { toast } from "sonner";

interface Tag {
  id: string;
  name: string;
  color?: string | null;
}

interface TagSelectorProps {
  selectedTagIds: string[];
  onChange: (tagIds: string[]) => void;
  availableTags: Tag[];
}

export function TagSelector({ selectedTagIds, onChange, availableTags }: TagSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [newTagName, setNewTagName] = useState("");
  const [isCreating, setIsCreating] = useState(false);
  const [localTags, setLocalTags] = useState<Tag[]>(availableTags);

  useEffect(() => {
    setLocalTags(availableTags);
  }, [availableTags]);

  const toggleTag = (tagId: string) => {
    if (selectedTagIds.includes(tagId)) {
      onChange(selectedTagIds.filter((id) => id !== tagId));
    } else {
      onChange([...selectedTagIds, tagId]);
    }
  };

  const handleCreateTag = async () => {
    if (!newTagName.trim()) return;
    setIsCreating(true);
    try {
      const res = await createTag({ name: newTagName.trim() });
      if (res.success && res.data) {
        const newTag = res.data as Tag;
        setLocalTags([...localTags, newTag]);
        onChange([...selectedTagIds, newTag.id]);
        setNewTagName("");
        toast.success(`Đã tạo tag #${newTag.name}`);
      } else {
        toast.error(res.error || "Lỗi khi tạo tag");
      }
    } finally {
      setIsCreating(false);
    }
  };

  const selectedTags = localTags.filter(t => selectedTagIds.includes(t.id));

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium">Thẻ (Tags)</span>
      </div>
      
      <div className="flex flex-wrap gap-1.5 min-h-[32px] p-1.5 border rounded-md bg-background/50">
        {selectedTags.length === 0 && (
          <span className="text-xs text-muted-foreground px-1 py-0.5 italic">Chưa gắn tag nào...</span>
        )}
        {selectedTags.map((tag) => (
          <Badge 
            key={tag.id} 
            variant="secondary" 
            className="pl-2 pr-1 h-6 gap-1 border-transparent hover:bg-secondary/80"
            style={{ 
              backgroundColor: tag.color ? `${tag.color}20` : undefined,
              color: tag.color || undefined,
              borderColor: tag.color || undefined
            }}
          >
            #{tag.name}
            <button 
              onClick={() => toggleTag(tag.id)}
              className="hover:bg-background/20 rounded-full p-0.5"
            >
              <X className="h-3 w-3" />
            </button>
          </Badge>
        ))}
        
        <Popover open={isOpen} onOpenChange={setIsOpen}>
          <PopoverTrigger asChild>
            <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] gap-1 border-dashed">
              <Plus className="h-3 w-3" />
              Gắn thẻ
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-64 p-3 space-y-3" align="start">
            <div className="flex flex-col gap-2">
              <div className="text-xs font-semibold text-muted-foreground flex items-center gap-1">
                <TagIcon className="h-3 w-3" /> CHỌN THẺ
              </div>
              <div className="max-h-40 overflow-y-auto flex flex-wrap gap-1.5">
                {localTags.length === 0 && (
                  <span className="text-[10px] text-muted-foreground italic w-full text-center py-2">Bạn chưa có tag nào...</span>
                )}
                {localTags.map((tag) => (
                  <button
                    key={tag.id}
                    onClick={() => toggleTag(tag.id)}
                    className={`text-[10px] px-2 py-1 rounded-full border transition-all flex items-center gap-1 ${
                      selectedTagIds.includes(tag.id)
                        ? "bg-primary text-primary-foreground border-primary"
                        : "bg-background hover:border-primary/50"
                    }`}
                  >
                    #{tag.name}
                    {selectedTagIds.includes(tag.id) && <Check className="h-2.5 w-2.5" />}
                  </button>
                ))}
              </div>
            </div>
            
            <div className="pt-2 border-t space-y-2">
              <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-tight">Tạo tag mới</div>
              <div className="flex gap-1.5">
                <Input 
                  placeholder="cv-hanoi, ban-be..." 
                  className="h-8 text-xs" 
                  value={newTagName}
                  onChange={(e) => setNewTagName(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), handleCreateTag())}
                />
                <Button 
                  size="sm" 
                  className="h-8 w-8 p-0" 
                  onClick={handleCreateTag}
                  disabled={isCreating || !newTagName.trim()}
                >
                  <Plus className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </PopoverContent>
        </Popover>
      </div>
    </div>
  );
}
