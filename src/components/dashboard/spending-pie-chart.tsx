"use client";

import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatCurrency, formatCurrencyCompact } from "@/lib/utils";

interface SpendingPieChartProps {
  data: {
    name: string;
    value: number;
    color: string;
  }[];
}

export function SpendingPieChart({ data }: SpendingPieChartProps) {

  return (
    <Card className="flex flex-col h-full border-none shadow-none">
      <CardHeader className="pb-0">
        <CardTitle className="text-sm font-medium">Phân bổ Chi tiêu (30 ngày)</CardTitle>
      </CardHeader>
      <CardContent className="flex-1 pb-0 min-h-[300px]">
        {data.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground text-xs italic">
            Chưa có biểu đồ
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="45%"
                innerRadius={60}
                outerRadius={80}
                paddingAngle={5}
                dataKey="value"
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                formatter={(value: string | number | undefined | readonly (string | number)[]) => [formatCurrency(Number(value || 0)), "Chi tiêu"]}
                contentStyle={{ borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
              />
              <Legend verticalAlign="bottom" height={36} iconType="circle" />
            </PieChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
