"use client";

import { 
  DropdownMenu, 
  DropdownMenuContent, 
  DropdownMenuItem, 
  DropdownMenuTrigger 
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Download, FileSpreadsheet, FileText } from "lucide-react";
import { toast } from "sonner";
import { format } from "date-fns";
import * as XLSX from "xlsx";

interface ExportButtonProps {
  data: any[];
  filename?: string;
}

export function ExportButton({ data, filename = "transactions-export" }: ExportButtonProps) {
  const getProcessedData = () => {
    return data.map(t => ({
      "Ngày": format(new Date(t.date), "dd/MM/yyyy"),
      "Mô tả": t.note || "",
      "Số tiền": Number(t.amount),
      "Loại": t.type === "INCOME" ? "Thu nhập" : t.type === "EXPENSE" ? "Chi tiêu" : "Chuyển khoản",
      "Danh mục": t.category?.name || "N/A",
      "Ví": t.wallet?.name || "N/A",
      "Ví nhận (Nếu CK)": t.toWallet?.name || ""
    }));
  };

  const exportToExcel = () => {
    if (!data || data.length === 0) {
      toast.error("Không có dữ liệu để xuất");
      return;
    }

    try {
      const worksheet = XLSX.utils.json_to_sheet(getProcessedData());
      const workbook = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(workbook, worksheet, "Transactions");
      
      const timestamp = format(new Date(), "yyyyMMdd_HHmmss");
      XLSX.writeFile(workbook, `${filename}_${timestamp}.xlsx`);
      
      toast.success("Đã xuất báo cáo Excel (.xlsx) thành công");
    } catch (error) {
      console.error("Excel Export error:", error);
      toast.error("Lỗi khi xuất file Excel");
    }
  };

  const exportToCSV = () => {
    if (!data || data.length === 0) {
      toast.error("Không có dữ liệu để xuất");
      return;
    }

    try {
      const processedData = getProcessedData();
      const headers = Object.keys(processedData[0]);
      
      const csvContent = [
        headers.join(","),
        ...processedData.map(row => 
          headers.map(header => {
            const val = row[header as keyof typeof row];
            return typeof val === 'string' ? `"${val}"` : val;
          }).join(",")
        )
      ].join("\n");

      const BOM = "\uFEFF";
      const blob = new Blob([BOM + csvContent], { type: "text/csv;charset=utf-8;" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      
      const timestamp = format(new Date(), "yyyyMMdd_HHmmss");
      link.setAttribute("href", url);
      link.setAttribute("download", `${filename}_${timestamp}.csv`);
      link.click();
      
      toast.success("Đã xuất báo cáo CSV thành công");
    } catch (error) {
      console.error("CSV Export error:", error);
      toast.error("Lỗi khi xuất file CSV");
    }
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button 
            variant="outline" 
            size="sm" 
            className="rounded-full hover:bg-primary/5 hover:text-primary border-primary/20 shadow-sm"
          >
            <Download className="mr-2 h-4 w-4" /> Xuất dữ liệu
          </Button>
        }
      />
      <DropdownMenuContent align="end" className="glass-card border-muted animate-in fade-in-0 zoom-in-95">
        <DropdownMenuItem onClick={exportToExcel} className="cursor-pointer gap-2 py-2.5">
          <FileSpreadsheet className="h-4 w-4 text-emerald-500" />
          <div className="flex flex-col">
            <span className="font-bold text-xs">Microsoft Excel (.xlsx)</span>
            <span className="text-[10px] text-muted-foreground">Khuyên dùng để phân tích</span>
          </div>
        </DropdownMenuItem>
        <DropdownMenuItem onClick={exportToCSV} className="cursor-pointer gap-2 py-2.5">
          <FileText className="h-4 w-4 text-blue-500" />
          <div className="flex flex-col">
            <span className="font-bold text-xs">Comma Separated Values (.csv)</span>
            <span className="text-[10px] text-muted-foreground">Tương thích với mọi hệ thống</span>
          </div>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
