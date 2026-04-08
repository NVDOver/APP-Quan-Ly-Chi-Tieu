"use client";

import { useState, useRef } from "react";
import { createWorker } from "tesseract.js";
import { Camera, Upload, Loader2, Check, X, SmartphoneIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";

interface ScannedData {
  amount?: number;
  date?: string;
  note?: string;
}

interface ReceiptScannerProps {
  onScanComplete: (data: ScannedData) => void;
}

export function ReceiptScanner({ onScanComplete }: ReceiptScannerProps) {
  const [open, setOpen] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const parseReceiptText = (text: string): ScannedData => {
    const lines = text.split("\n").map(l => l.trim()).filter(l => l.length > 0);
    const result: ScannedData = {};

    // 1. Trích xuất tên cửa hàng (Thường là dòng đầu tiên)
    if (lines.length > 0) {
      result.note = lines[0].substring(0, 50);
    }

    // 2. Logic trích xuất số tiền cải tiến
    const extractAmount = (line: string): number | null => {
      // Tìm số có phân cách hàng nghìn (.,) hoặc số liền mạch 4-12 chữ số
      const matches = line.match(/(\d{1,3}([\.,]\d{3})+)|(\d{4,12})/);
      if (matches) {
        const raw = matches[0].replace(/[\.,]/g, "");
        const val = parseInt(raw);
        return isNaN(val) ? null : val;
      }
      return null;
    };

    // Từ khóa ưu tiên (Cao)
    const priorityRegex = /tổng cộng|thành tiền|tổng tiền|tổng thanh toán|cần thanh toán|tổng phải trả|total|amount due|grand total/i;
    // Từ khóa loại trừ (Tiền thừa, tiền khách đưa...)
    const excludeRegex = /tiền thừa|tiền trả lại|change|thừa|trả lại|khách đưa|khách trả|tiền mặt|paid|tendered/i;
    // Từ khóa thuế (để bỏ qua)
    const vatRegex = /vat|thuế/i;

    let candidates: { amount: number; lineIndex: number; isPriority: boolean }[] = [];

    lines.forEach((line, index) => {
      const amount = extractAmount(line);
      if (amount && amount > 1000) { // Bỏ qua các số quá nhỏ (không phải tiền thanh toán ở VN)
        const isExcluded = excludeRegex.test(line);
        const isPriority = priorityRegex.test(line);
        const isVat = vatRegex.test(line);

        if (!isExcluded && !isVat) {
          candidates.push({ amount, lineIndex: index, isPriority });
        }
      }
    });

    if (candidates.length > 0) {
      // Tìm số tiền lớn nhất để làm mốc so sánh
      const maxAmount = Math.max(...candidates.map(c => c.amount));
      
      // Lọc bỏ những số tiền quá nhỏ so với số lớn nhất (thường là đơn giá hoặc VAT lẻ)
      // Chỉ giữ lại những số tiền >= 20% số lớn nhất
      candidates = candidates.filter(c => c.amount >= maxAmount * 0.2);

      // Sắp xếp theo mức độ ưu tiên:
      // 1. Dòng có từ khóa ưu tiên (isPriority)
      // 2. Số tiền lớn hơn
      // 3. Dòng ở vị trí dưới cùng của hóa đơn (lineIndex cao hơn)
      candidates.sort((a, b) => {
        if (a.isPriority !== b.isPriority) return a.isPriority ? -1 : 1;
        if (Math.abs(a.amount - b.amount) > 100) return b.amount - a.amount; // Ưu tiên số tiền lớn hơn
        return b.lineIndex - a.lineIndex; // Ưu tiên dòng ở dưới
      });

      result.amount = candidates[0].amount;
    }

    // 3. Trích xuất ngày (Giữ nguyên logic cũ nhưng có cải tiến nhẹ)
    for (const line of lines) {
      const dateMatch = line.match(/(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4})/);
      if (dateMatch) {
        const dateStr = dateMatch[0].replace(/-/g, "/");
        const parts = dateStr.split("/");
        try {
          let day, month, year;
          if (parts.length === 3) {
            if (parts[0].length === 4) [year, month, day] = parts;
            else [day, month, year] = parts;
            if (year.length === 2) year = "20" + year;
            const formattedDate = `${year}-${month.padStart(2, "0")}-${day.padStart(2, "0")}`;
            if (!isNaN(Date.parse(formattedDate))) {
              result.date = formattedDate;
              break;
            }
          }
        } catch (e) {
          console.error("Date parse error:", e);
        }
      }
    }

    return result;
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setPreviewUrl(URL.createObjectURL(file));
    setIsProcessing(true);
    setProgress(0);

    try {
      const worker = await createWorker("vie", 1, {
        logger: m => {
          if (m.status === "recognizing text") {
            setProgress(Math.round(m.progress * 100));
          }
        }
      });

      const { data: { text } } = await worker.recognize(file);
      await worker.terminate();

      console.log("OCR Result:", text);
      const data = parseReceiptText(text);
      
      if (data.amount || data.note || data.date) {
        onScanComplete(data);
        toast.success("Đã trích xuất thông tin hóa đơn!");
        handleClose();
      } else {
        toast.error("Không tìm thấy thông tin trên hóa đơn. Vui lòng chụp rõ hơn.");
      }
    } catch (error) {
      console.error("OCR Error:", error);
      toast.error("Gặp lỗi khi xử lý ảnh. Vui lòng thử lại.");
    } finally {
      setIsProcessing(false);
    }
  };

  const handleClose = () => {
    setOpen(false);
    setIsProcessing(false);
    setPreviewUrl(null);
    setProgress(0);
  };

  return (
    <>
      <Button 
        type="button" 
        variant="outline" 
        className="w-full flex items-center justify-center gap-2 border-dashed border-primary/50 hover:border-primary transition-all py-6 bg-primary/5"
        onClick={() => setOpen(true)}
      >
        <Camera className="h-5 w-5 text-primary" />
        <span className="font-semibold text-primary">📸 Quét từ hóa đơn</span>
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Quét hóa đơn thông minh</DialogTitle>
          </DialogHeader>
          
          <div className="flex flex-col items-center justify-center gap-6 py-8">
            {!previewUrl ? (
              <div className="grid grid-cols-2 gap-4 w-full">
                <Button 
                  variant="secondary" 
                  className="flex flex-col h-32 gap-2 rounded-2xl"
                  onClick={() => fileInputRef.current?.click()}
                >
                  <Upload className="h-8 w-8 text-muted-foreground" />
                  <span>Chọn từ thư viện</span>
                </Button>
                
                <Button 
                  variant="secondary" 
                  className="flex flex-col h-32 gap-2 rounded-2xl relative overflow-hidden"
                  onClick={() => {
                    if (fileInputRef.current) {
                        fileInputRef.current.setAttribute("capture", "environment");
                        fileInputRef.current.click();
                    }
                  }}
                >
                  <SmartphoneIcon className="h-8 w-8 text-muted-foreground" />
                  <span>Chụp ảnh trực tiếp</span>
                </Button>
              </div>
            ) : (
              <div className="w-full space-y-4">
                <div className="relative aspect-[3/4] w-full overflow-hidden rounded-xl border bg-muted">
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img src={previewUrl} alt="Preview" className="h-full w-full object-contain" />
                  
                  {isProcessing && (
                    <div className="absolute inset-0 flex flex-col items-center justify-center bg-background/60 backdrop-blur-sm">
                      <Loader2 className="h-10 w-10 animate-spin text-primary" />
                      <p className="mt-4 font-medium text-primary">Đang phân tích: {progress}%</p>
                      <Progress value={progress} className="mt-2 w-3/4 h-2" />
                    </div>
                  )}
                </div>
              </div>
            )}

            <input 
              type="file" 
              ref={fileInputRef} 
              className="hidden" 
              accept="image/*" 
              onChange={handleFileChange} 
            />
          </div>

          <DialogFooter className="sm:justify-start">
            <Button type="button" variant="ghost" onClick={handleClose} disabled={isProcessing}>
              Hủy bỏ
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
