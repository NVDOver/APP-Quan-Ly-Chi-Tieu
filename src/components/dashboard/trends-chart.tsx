"use client";

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';
import { formatCurrency, formatCurrencyCompact } from "@/lib/utils";
interface TrendsChartProps {
  data: { label: string; income: number; expense: number }[];
}

export function TrendsChart({ data }: TrendsChartProps) {
  return (
    <div className="h-[400px] w-full mt-4">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={data}
          margin={{
            top: 10,
            right: 30,
            left: 0,
            bottom: 0,
          }}
        >
          <defs>
            <linearGradient id="colorIncome" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#10b981" stopOpacity={0.1} />
              <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="colorExpense" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.1} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
          <XAxis
            dataKey="label"
            axisLine={false}
            tickLine={false}
            tick={{ fill: '#64748b', fontSize: 12 }}
            dy={10}
          />
          <YAxis
            axisLine={false}
            tickLine={false}
            tick={{ fill: '#64748b', fontSize: 10 }}
            tickFormatter={(value) => formatCurrencyCompact(value)}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: 'rgba(255, 255, 255, 0.8)',
              borderRadius: '12px',
              border: 'none',
              boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
              backdropFilter: 'blur(8px)'
            }}
            formatter={(value: string | number | undefined | readonly (string | number)[]) => [formatCurrency(Number(value || 0)), ""]}
          />
          <Legend verticalAlign="top" height={36} />
          <Area
            type="monotone"
            dataKey="income"
            name="Thu nhập"
            stroke="#10b981"
            strokeWidth={3}
            fillOpacity={1}
            fill="url(#colorIncome)"
          />
          <Area
            type="monotone"
            dataKey="expense"
            name="Chi tiêu"
            stroke="#ef4444"
            strokeWidth={3}
            fillOpacity={1}
            fill="url(#colorExpense)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
