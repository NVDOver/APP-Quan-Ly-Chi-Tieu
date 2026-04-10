# Hướng dẫn Khắc phục Toàn diện — Dự án Quản lý Chi tiêu
> Mục tiêu: Nâng điểm từ 5.7 → 10/10 trên tất cả 5 tiêu chí

---

## Mục lục thứ tự ưu tiên

| # | Hạng mục | Mức độ | Tiêu chí |
|---|---|---|---|
| 1 | Fix middleware bảo vệ toàn bộ routes | CRITICAL | Bảo mật |
| 2 | Fix SavingGoal desync khi xóa transaction | CRITICAL | Database |
| 3 | Fix deleteWallet thiếu userId filter | HIGH | Bảo mật |
| 4 | Chuẩn hóa error handling toàn bộ actions | HIGH | Code Quality |
| 5 | Loại bỏ toàn bộ `any`, thêm Prisma types | HIGH | TypeScript |
| 6 | Tách `formatCurrency` vào lib/utils | HIGH | DRY |
| 7 | Thay `alert()` bằng `sonner` toast | HIGH | UX |
| 8 | Fix double auth() call | MEDIUM | Architecture |
| 9 | Fix `getCashFlowTrend` N+1 | MEDIUM | Database |
| 10 | Thêm Suspense boundaries + Skeleton | MEDIUM | Architecture |
| 11 | Refactor WalletsPage → Server Component | MEDIUM | Architecture |
| 12 | Fix animation delays quá cao | MEDIUM | UX |
| 13 | Fix `updateProfile` không check email unique | MEDIUM | Bảo mật |
| 14 | Fix `revalidatePath` scope | LOW | Architecture |
| 15 | Fix `DialogTrigger render={}` sai API | LOW | UI |
| 16 | Thêm PWA offline page | LOW | UX |
| 17 | Xóa file rác `get-categories.ts` | LOW | Code Quality |
| 18 | Thêm `error.tsx` và `loading.tsx` | LOW | Architecture |

---

## PHẦN 1 — BẢO MẬT (CRITICAL)

### 1.1 — Fix Middleware: Bảo vệ toàn bộ dashboard routes

**Vấn đề:** `auth.config.ts` hiện tại chỉ bảo vệ đúng một route `/`. Tất cả `/transactions`, `/wallets`, `/budgets`, `/categories`, `/saving-goals`, `/reports`, `/profile` đều không được middleware bảo vệ — unauthenticated users có thể truy cập và nhận raw error thay vì redirect về login.

**Sửa file: `src/lib/auth.config.ts`**

```typescript
import type { NextAuthConfig } from 'next-auth';

// Danh sách public routes không cần auth
const PUBLIC_ROUTES = ['/login', '/register'];
// Route gốc sau khi đăng nhập
const DEFAULT_LOGIN_REDIRECT = '/';

export const authConfig = {
  pages: {
    signIn: '/login',
  },
  callbacks: {
    authorized({ auth, request: { nextUrl } }) {
      const isLoggedIn = !!auth?.user;
      const isPublicRoute = PUBLIC_ROUTES.some(route =>
        nextUrl.pathname.startsWith(route)
      );

      // Nếu đang ở auth route mà đã đăng nhập → redirect về dashboard
      if (isPublicRoute) {
        if (isLoggedIn) {
          return Response.redirect(new URL(DEFAULT_LOGIN_REDIRECT, nextUrl));
        }
        return true; // Cho phép vào trang login/register
      }

      // Mọi route còn lại đều cần đăng nhập
      return isLoggedIn;
      // NextAuth tự động redirect về pages.signIn nếu return false
    },
    async session({ session, token }) {
      if (token.sub && session.user) {
        session.user.id = token.sub;
      }
      return session;
    },
    async jwt({ token, user }) {
      if (user) {
        token.sub = user.id;
      }
      return token;
    },
  },
  providers: [],
} satisfies NextAuthConfig;
```

**Sửa file: `src/middleware.ts`**

```typescript
import NextAuth from 'next-auth';
import { authConfig } from '@/lib/auth.config';

export default NextAuth(authConfig).auth;

export const config = {
  /*
   * Chạy middleware trên TẤT CẢ routes NGOẠI TRỪ:
   * - /api/* (API routes tự xử lý auth)
   * - /_next/static (static files)
   * - /_next/image (image optimization)
   * - /favicon.ico, /manifest.json, /icons/* (public assets)
   * - files có extension (.png, .svg, .jpg...)
   */
  matcher: [
    '/((?!api|_next/static|_next/image|favicon\\.ico|manifest\\.json|icons|.*\\.(?:png|svg|jpg|jpeg|gif|webp)$).*)',
  ],
};
```

**Xóa bỏ các `redirect("/login")` thủ công trong pages** vì giờ middleware đã xử lý:

```typescript
// TRƯỚC — dashboard/page.tsx, budgets/page.tsx, v.v.
export default async function DashboardPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login"); // Xóa dòng này
  ...
}

// SAU — Middleware đã bảo vệ, chỉ cần lấy session
export default async function DashboardPage() {
  const session = await auth();
  const userId = session!.user!.id; // TypeScript biết session luôn tồn tại
  ...
}
```

---

### 1.2 — Fix deleteWallet: Thiếu userId filter

**Vấn đề:** Đang count transactions của toàn bộ hệ thống thay vì chỉ của user hiện tại, gây rò rỉ thông tin.

**Sửa file: `src/app/actions/wallet-actions.ts`**

```typescript
export async function deleteWallet(id: string) {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    // FIX: Thêm userId vào filter để chỉ count transactions của user này
    const transactionCount = await prisma.transaction.count({
      where: {
        userId, // <- BẮT BUỘC phải có
        OR: [
          { walletId: id },
          { toWalletId: id },
        ],
      },
    });

    if (transactionCount > 0) {
      throw new Error(
        "Không thể xóa ví đã có giao dịch. Hãy xóa các giao dịch trước."
      );
    }

    await prisma.wallet.delete({
      where: { id, userId },
    });

    revalidatePath("/wallets");
    revalidatePath("/");
    return { success: true };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Đã xảy ra lỗi",
    };
  }
}
```

---

### 1.3 — Fix updateProfile: Kiểm tra email unique trước khi update

**Sửa file: `src/app/actions/profile-actions.ts`**

```typescript
export async function updateProfile(data: z.infer<typeof profileSchema>) {
  try { // Thêm try/catch
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    const validated = profileSchema.parse(data);

    // Nếu đổi email, kiểm tra xem email mới có bị dùng bởi user khác không
    if (validated.email !== session.user.email) {
      const existingUser = await prisma.user.findUnique({
        where: { email: validated.email },
      });
      if (existingUser && existingUser.id !== userId) {
        return { success: false, error: "Email này đã được sử dụng bởi tài khoản khác." };
      }
    }

    await prisma.user.update({
      where: { id: userId },
      data: {
        fullName: validated.fullName,
        email: validated.email,
        avatarUrl: validated.avatarUrl || null,
        currency: validated.currency,
      },
    });

    revalidatePath("/profile");
    revalidatePath("/");
    return { success: true };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Đã xảy ra lỗi",
    };
  }
}

export async function updatePassword(data: z.infer<typeof passwordSchema>) {
  try { // Thêm try/catch
    const session = await auth();
    if (!session?.user?.email) throw new Error("Unauthorized");
    const email = session.user.email;

    const validated = passwordSchema.parse(data);

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) throw new Error("User not found");

    const isValid = await bcrypt.compare(validated.currentPassword, user.passwordHash);
    if (!isValid) {
      return { success: false, error: "Mật khẩu hiện tại không đúng." };
    }

    const hashedPassword = await bcrypt.hash(validated.newPassword, 10);
    await prisma.user.update({
      where: { email },
      data: { passwordHash: hashedPassword },
    });

    return { success: true };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Đã xảy ra lỗi",
    };
  }
}
```

---

## PHẦN 2 — DATABASE & PRISMA (CRITICAL)

### 2.1 — Fix SavingGoal Desync: Schema Migration

**Vấn đề cốt lõi:** Khi `addContribution` chạy, nó tạo một EXPENSE transaction thông thường nhưng không có cách nào biết transaction này liên quan đến saving goal nào. Khi user xóa transaction đó, `wallet.balance` được hoàn lại nhưng `savingGoal.currentAmount` KHÔNG được trừ lại — dữ liệu sai vĩnh viễn.

**Bước 1: Cập nhật `prisma/schema.prisma`**

Thêm trường `savingGoalId` vào model `Transaction`:

```prisma
model Transaction {
  id           String          @id @default(cuid())
  userId       String          @map("user_id")
  walletId     String          @map("wallet_id")
  toWalletId   String?         @map("to_wallet_id")
  categoryId   String?         @map("category_id")
  savingGoalId String?         @map("saving_goal_id") // <- THÊM TRƯỜNG NÀY
  amount       Decimal         @db.Decimal(19, 4)
  date         DateTime        @db.Timestamptz
  note         String?
  receiptUrl   String?         @map("receipt_url")
  type         TransactionType
  createdAt    DateTime        @default(now()) @map("created_at") @db.Timestamptz
  updatedAt    DateTime        @updatedAt @map("updated_at") @db.Timestamptz

  user        User        @relation(fields: [userId], references: [id], onDelete: Cascade)
  wallet      Wallet      @relation("FromWallet", fields: [walletId], references: [id], onDelete: Cascade)
  toWallet    Wallet?     @relation("ToWallet", fields: [toWalletId], references: [id], onDelete: SetNull)
  category    Category?   @relation(fields: [categoryId], references: [id], onDelete: SetNull)
  savingGoal  SavingGoal? @relation(fields: [savingGoalId], references: [id], onDelete: SetNull) // <- THÊM RELATION

  @@index([userId])
  @@index([walletId])
  @@index([categoryId])
  @@index([savingGoalId]) // <- THÊM INDEX
  @@index([date])
  @@map("transactions")
}

model SavingGoal {
  id            String   @id @default(cuid())
  userId        String   @map("user_id")
  name          String
  targetAmount  Decimal  @map("target_amount") @db.Decimal(19, 4)
  currentAmount Decimal  @default(0) @map("current_amount") @db.Decimal(19, 4)
  deadlineDate  DateTime @map("deadline_date") @db.Date
  createdAt     DateTime @default(now()) @map("created_at") @db.Timestamptz
  updatedAt     DateTime @updatedAt @map("updated_at") @db.Timestamptz

  user         User          @relation(fields: [userId], references: [id], onDelete: Cascade)
  transactions Transaction[] // <- THÊM RELATION NGƯỢC

  @@index([userId])
  @@map("saving_goals")
}
```

**Bước 2: Chạy migration**

```bash
npx prisma migrate dev --name add_saving_goal_id_to_transaction
```

**Bước 3: Cập nhật `addContribution` trong `saving-goal-actions.ts`**

```typescript
export async function addContribution(
  goalId: string,
  walletId: string,
  amount: number,
  note?: string
) {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    if (amount <= 0) throw new Error("Số tiền nạp phải lớn hơn 0");

    await prisma.$transaction(async (tx) => {
      // 1. Kiểm tra goal thuộc về user này
      const goal = await tx.savingGoal.findUnique({
        where: { id: goalId, userId },
      });
      if (!goal) throw new Error("Không tìm thấy mục tiêu tiết kiệm");

      // 2. Kiểm tra ví và số dư
      const wallet = await tx.wallet.findUnique({
        where: { id: walletId, userId },
      });
      if (!wallet) throw new Error("Không tìm thấy ví");
      if (Number(wallet.balance) < amount) {
        throw new Error("Số dư ví không đủ để nạp vào mục tiêu");
      }

      // 3. Trừ tiền ví
      await tx.wallet.update({
        where: { id: walletId },
        data: { balance: { decrement: amount } },
      });

      // 4. Cộng tiền vào mục tiêu
      await tx.savingGoal.update({
        where: { id: goalId },
        data: { currentAmount: { increment: amount } },
      });

      // 5. Tạo transaction với savingGoalId để tracking
      await tx.transaction.create({
        data: {
          userId,
          walletId,
          savingGoalId: goalId, // <- LIÊN KẾT VỚI SAVING GOAL
          amount,
          type: "EXPENSE",
          date: new Date(),
          note: note || `Nạp tiền vào mục tiêu: ${goal.name}`,
        },
      });
    });

    revalidatePath("/saving-goals");
    revalidatePath("/wallets");
    revalidatePath("/transactions");
    revalidatePath("/");
    return { success: true };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Đã xảy ra lỗi",
    };
  }
}
```

**Bước 4: Cập nhật `deleteTransaction` để đồng bộ saving goal**

```typescript
export async function deleteTransaction(transactionId: string) {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    await prisma.$transaction(async (tx) => {
      const transaction = await tx.transaction.findUnique({
        where: { id: transactionId, userId },
      });
      if (!transaction) throw new Error("Giao dịch không tồn tại");

      // Hoàn trả số dư ví
      if (transaction.type === "TRANSFER") {
        await tx.wallet.update({
          where: { id: transaction.walletId, userId },
          data: { balance: { increment: transaction.amount } },
        });
        if (transaction.toWalletId) {
          await tx.wallet.update({
            where: { id: transaction.toWalletId, userId },
            data: { balance: { decrement: transaction.amount } },
          });
        }
      } else {
        await tx.wallet.update({
          where: { id: transaction.walletId, userId },
          data: {
            balance:
              transaction.type === "INCOME"
                ? { decrement: transaction.amount }
                : { increment: transaction.amount },
          },
        });
      }

      // FIX: Nếu transaction này liên quan đến saving goal → hoàn trả
      if (transaction.savingGoalId) {
        await tx.savingGoal.update({
          where: { id: transaction.savingGoalId },
          data: { currentAmount: { decrement: transaction.amount } },
        });
      }

      await tx.transaction.delete({ where: { id: transactionId } });
    });

    revalidatePath("/");
    revalidatePath("/transactions");
    revalidatePath("/saving-goals"); // Thêm revalidate saving-goals
    return { success: true };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : "Đã xảy ra lỗi",
    };
  }
}
```

---

### 2.2 — Fix getCashFlowTrend: Dùng DB aggregation thay vì in-memory

**Sửa file: `src/app/actions/report-actions.ts`**

```typescript
export async function getCashFlowTrend() {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    // Tạo danh sách 6 tháng gần nhất (metadata)
    const months = Array.from({ length: 6 }).map((_, i) => {
      const d = new Date();
      d.setDate(1);
      d.setMonth(d.getMonth() - (5 - i));
      d.setHours(0, 0, 0, 0);
      return {
        start: new Date(d),
        end: new Date(d.getFullYear(), d.getMonth() + 1, 0, 23, 59, 59, 999),
        key: `${d.getFullYear()}-${(d.getMonth() + 1).toString().padStart(2, "0")}`,
        label: `Tháng ${d.getMonth() + 1}/${d.getFullYear()}`,
        income: 0,
        expense: 0,
      };
    });

    const sixMonthsAgo = months[0].start;

    // Dùng groupBy thay vì load toàn bộ transaction vào memory
    // Prisma chưa hỗ trợ group by tháng trực tiếp → dùng $queryRaw
    const result = await prisma.$queryRaw<
      Array<{ month_key: string; type: string; total: number }>
    >`
      SELECT
        TO_CHAR(date, 'YYYY-MM') AS month_key,
        type,
        SUM(amount)::float AS total
      FROM transactions
      WHERE
        user_id = ${userId}
        AND date >= ${sixMonthsAgo}
        AND type IN ('INCOME', 'EXPENSE')
      GROUP BY month_key, type
      ORDER BY month_key ASC
    `;

    // Map kết quả vào cấu trúc months
    result.forEach((row) => {
      const month = months.find((m) => m.key === row.month_key);
      if (month) {
        if (row.type === "INCOME") month.income = Number(row.total);
        if (row.type === "EXPENSE") month.expense = Number(row.total);
      }
    });

    // Trả về chỉ các trường cần thiết cho UI
    return {
      success: true,
      data: months.map(({ key, label, income, expense }) => ({
        key,
        label,
        income,
        expense,
      })),
    };
  } catch (error) {
    if (error instanceof Error) console.error("Trend Error:", error.message);
    return { success: false, error: "Lỗi tải biểu đồ xu hướng" };
  }
}
```

---

## PHẦN 3 — CODE QUALITY & TYPESCRIPT

### 3.1 — Tạo shared utilities trong `lib/utils.ts`

**Sửa file: `src/lib/utils.ts`** (bổ sung vào file hiện có)

```typescript
import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Format số tiền theo locale Việt Nam.
 * @param amount - Số tiền cần format
 * @param currency - Mã tiền tệ (mặc định: VND)
 */
export function formatCurrency(amount: number, currency = "VND"): string {
  return new Intl.NumberFormat("vi-VN", {
    style: "currency",
    currency,
    minimumFractionDigits: currency === "VND" ? 0 : 2,
    maximumFractionDigits: currency === "VND" ? 0 : 2,
  }).format(amount);
}

/**
 * Format số tiền ngắn gọn cho biểu đồ (ví dụ: 1,500,000 → 1.5M)
 */
export function formatCurrencyCompact(amount: number): string {
  if (amount >= 1_000_000) {
    return `${(amount / 1_000_000).toFixed(1)}M`;
  }
  if (amount >= 1_000) {
    return `${(amount / 1_000).toFixed(0)}k`;
  }
  return amount.toString();
}
```

**Sau đó, xóa tất cả các định nghĩa `formatCurrency` local trong:**
- `src/app/(dashboard)/page.tsx`
- `src/app/(dashboard)/transactions/page.tsx`
- `src/app/(dashboard)/budgets/page.tsx`
- `src/app/(dashboard)/wallets/page.tsx`
- `src/components/dashboard/income-expense-chart.tsx`
- `src/components/dashboard/spending-pie-chart.tsx`
- `src/components/dashboard/trends-chart.tsx`

**Và import từ utils:**
```typescript
import { formatCurrency, formatCurrencyCompact } from "@/lib/utils";
```

---

### 3.2 — Chuẩn hóa Error Handling: Tạo ActionResult type

**Tạo file mới: `src/lib/action-types.ts`**

```typescript
/**
 * Type chuẩn cho tất cả Server Action responses.
 * Đảm bảo consistency toàn bộ codebase.
 */
export type ActionResult<T = undefined> =
  | { success: true; data?: T }
  | { success: false; error: string };

/**
 * Helper để tạo success result
 */
export function actionSuccess<T>(data?: T): ActionResult<T> {
  return { success: true, data };
}

/**
 * Helper để tạo error result từ unknown error
 */
export function actionError(error: unknown, fallback = "Đã xảy ra lỗi"): ActionResult {
  if (error instanceof Error) {
    return { success: false, error: error.message };
  }
  return { success: false, error: fallback };
}
```

**Áp dụng cho `budget-actions.ts`** (action hiện tại throw thay vì return):

```typescript
import { ActionResult, actionSuccess, actionError } from "@/lib/action-types";

export async function upsertBudget(
  data: z.infer<typeof budgetSchema>
): Promise<ActionResult> {
  try {
    const session = await auth();
    if (!session?.user?.id) return { success: false, error: "Unauthorized" };
    const userId = session.user.id;

    const validated = budgetSchema.parse(data);
    const normalizedMonth = startOfMonth(validated.monthYear);

    await prisma.budget.upsert({
      where: {
        userId_categoryId_monthYear: {
          userId,
          categoryId: validated.categoryId,
          monthYear: normalizedMonth,
        },
      },
      update: { limitAmount: validated.limitAmount },
      create: {
        userId,
        categoryId: validated.categoryId,
        limitAmount: validated.limitAmount,
        monthYear: normalizedMonth,
      },
    });

    revalidatePath("/budgets");
    revalidatePath("/");
    return actionSuccess();
  } catch (error) {
    return actionError(error);
  }
}
```

---

### 3.3 — Loại bỏ `any`, thêm Prisma types

**Sửa `src/app/(dashboard)/transactions/page.tsx`:**

```typescript
import type { Transaction, Wallet, Category } from "@prisma/client";

// Type chính xác từ Prisma (thay vì any)
type TransactionWithRelations = Transaction & {
  wallet: Wallet;
  toWallet: Wallet | null;
  category: Category | null;
};

// Trong JSX:
{transactions.map((t: TransactionWithRelations) => (
  // ...
))}
```

**Sửa `src/components/fab.tsx`** — xóa `as any` trong resolver:

```typescript
// Vấn đề: Zod v4 có breaking change với @hookform/resolvers
// CÁCH 1: Downgrade zodResolver hoặc dùng superRefine thay vì chained .refine()

// Cách tiếp cận tốt hơn — dùng superRefine (1 lần, không chain):
const transactionSchema = transactionBaseSchema.superRefine((data, ctx) => {
  if (data.type === "TRANSFER") {
    if (!data.toWalletId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Vui lòng chọn ví nhận",
        path: ["toWalletId"],
      });
    }
    if (data.walletId === data.toWalletId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Ví nguồn và ví nhận phải khác nhau",
        path: ["toWalletId"],
      });
    }
  } else {
    if (!data.categoryId) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Vui lòng chọn danh mục",
        path: ["categoryId"],
      });
    }
  }
});

// Bỏ `as any`:
const form = useForm<TransactionFormValues>({
  resolver: zodResolver(transactionSchema), // Không cần as any nữa
  defaultValues: { ... },
});
```

**Sửa các `// eslint-disable-next-line @typescript-eslint/no-explicit-any` trong chart components:**

```typescript
// income-expense-chart.tsx và spending-pie-chart.tsx
// Thay formatter type any → number
formatter={(value: number) => [
  formatCurrency(Number(value)) + " ₫",
  "",
]}
```

---

### 3.4 — Thay `alert()` bằng Sonner toast

**Sửa `src/components/fab.tsx`:**

```typescript
import { toast } from "sonner";

// Xóa: alert(res.error || "Gặp lỗi khi tạo giao dịch");
// Thêm:
if (res.success) {
  setOpen(false);
  form.reset({ type: "EXPENSE", amount: 0, date: new Date().toISOString().split("T")[0] });
  toast.success("Đã lưu giao dịch thành công!");
} else {
  toast.error(res.error || "Gặp lỗi khi tạo giao dịch");
}
```

**Đảm bảo `<Toaster />` được mount trong app layout:**

```typescript
// src/app/layout.tsx
import { Toaster } from "sonner";

export default function RootLayout({ children }) {
  return (
    <html lang="vi" suppressHydrationWarning>
      <body ...>
        <Providers>
          {children}
          <Toaster richColors position="top-right" /> {/* <- THÊM */}
        </Providers>
      </body>
    </html>
  );
}
```

---

### 3.5 — Xóa file rác `get-categories.ts`

File `src/app/actions/get-categories.ts` duplicate logic với `getFormOptions` trong `transaction-actions.ts`. Kiểm tra không có file nào import nó rồi xóa:

```bash
# Kiểm tra trước khi xóa
grep -r "get-categories" src/

# Nếu không có kết quả → xóa an toàn
rm src/app/actions/get-categories.ts
```

---

## PHẦN 4 — KIẾN TRÚC NEXT.JS

### 4.1 — Fix double auth() call

**Vấn đề:** `dashboard/page.tsx` gọi `auth()` rồi gọi `getDashboardStats()` và `getBudgetsWithProgress()` — mỗi function này lại gọi `auth()` lại từ đầu.

**Giải pháp:** Truyền `userId` làm tham số thay vì để mỗi function tự gọi auth.

**Sửa `src/app/actions/dashboard-actions.ts`:**

```typescript
// Trước: getDashboardStats() tự gọi auth() bên trong
// Sau: nhận userId từ bên ngoài

export async function getDashboardStats(userId: string) {
  // Xóa: const session = await auth(); if (!session?.user?.id) throw ...
  // Dùng trực tiếp userId được truyền vào
  
  const thirtyDaysAgo = startOfDay(subDays(new Date(), 30));
  // ... phần còn lại giữ nguyên
}
```

**Sửa `src/app/actions/budget-actions.ts`:**

```typescript
export async function getBudgetsWithProgress(userId: string) {
  // Xóa auth() call bên trong, dùng userId tham số
  // ... phần còn lại giữ nguyên
}
```

**Sửa `src/app/(dashboard)/page.tsx`:**

```typescript
export default async function DashboardPage() {
  const session = await auth(); // CHỈ gọi auth() 1 LẦN
  const userId = session!.user!.id;

  const [wallets, categories, savingGoals, stats, dbUser] = await Promise.all([
    prisma.wallet.findMany({ where: { userId } }),
    prisma.category.findMany({ where: { userId, isDeleted: false } }),
    prisma.savingGoal.findMany({ where: { userId } }),
    getDashboardStats(userId),  // Truyền userId
    prisma.user.findUnique({ where: { id: userId } }),
  ]);
  // ...
}
```

**Sửa `src/components/dashboard/budget-alerts.tsx`:**

```typescript
// Bây giờ component này cần nhận userId từ parent (dashboard page)
// HOẶC: Giữ nguyên server component self-contained vì nó là leaf component
// Tùy chọn 2 (đơn giản hơn): Giữ auth() call trong BudgetAlerts vì đây là 
// component độc lập, không phải bottleneck lớn. Tập trung fix ở dashboard page.
```

---

### 4.2 — Thêm Suspense Boundaries + Loading States

**Tạo `src/app/(dashboard)/loading.tsx`:**

```typescript
import { Skeleton } from "@/components/ui/skeleton";

export default function DashboardLoading() {
  return (
    <div className="flex flex-col space-y-8">
      {/* Stats row */}
      <div className="grid gap-4 md:grid-cols-3">
        {[1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-28 w-full rounded-xl" />
        ))}
      </div>
      {/* Charts row */}
      <div className="grid gap-4 grid-cols-1 lg:grid-cols-4">
        <Skeleton className="h-72 rounded-xl" />
        <Skeleton className="h-72 col-span-2 rounded-xl" />
        <Skeleton className="h-72 rounded-xl" />
      </div>
    </div>
  );
}
```

**Tạo `src/app/(dashboard)/error.tsx`:**

```typescript
"use client";

import { useEffect } from "react";
import { Button } from "@/components/ui/button";
import { AlertCircle } from "lucide-react";

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("Dashboard error:", error);
  }, [error]);

  return (
    <div className="flex flex-col items-center justify-center min-h-[400px] gap-4">
      <div className="flex h-16 w-16 items-center justify-center rounded-full bg-destructive/10">
        <AlertCircle className="h-8 w-8 text-destructive" />
      </div>
      <h2 className="text-xl font-semibold">Có lỗi xảy ra</h2>
      <p className="text-sm text-muted-foreground text-center max-w-md">
        {error.message || "Không thể tải trang. Vui lòng thử lại."}
      </p>
      <Button onClick={reset} variant="outline">
        Thử lại
      </Button>
    </div>
  );
}
```

**Áp dụng Suspense trong `dashboard/page.tsx`:**

```typescript
import { Suspense } from "react";
import { Skeleton } from "@/components/ui/skeleton";

export default async function DashboardPage() {
  // ... auth và data fetching

  return (
    <div className="flex flex-col space-y-8">
      {/* BudgetAlerts tự fetch → wrap Suspense để không block page */}
      <Suspense fallback={null}>
        <BudgetAlerts />
      </Suspense>

      {/* ... phần còn lại */}
    </div>
  );
}
```

---

### 4.3 — Fix revalidatePath scope

**Thay đổi áp dụng toàn bộ actions:**

```typescript
// TRƯỚC — chỉ revalidate đúng segment
revalidatePath("/");
revalidatePath("/transactions");

// SAU — revalidate toàn bộ layout tree
revalidatePath("/", "layout"); // Invalidate toàn bộ app từ root
// Hoặc nếu chỉ muốn invalidate page cụ thể:
revalidatePath("/transactions", "page");
```

---

### 4.4 — Refactor WalletsPage từ Client → Server Component

`WalletsPage` hiện tại là `"use client"` và dùng `useEffect` để fetch data — đây là anti-pattern trong App Router. CRUD operations thì vẫn cần client, nhưng initial data load nên từ server.

**Tạo `src/app/(dashboard)/wallets/page.tsx` mới:**

```typescript
// Server Component — không có "use client"
import { auth } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { WalletsClient } from "./wallets-client"; // Client part tách riêng

export default async function WalletsPage() {
  const session = await auth();
  const userId = session!.user!.id;

  const wallets = await prisma.wallet.findMany({
    where: { userId },
    orderBy: { createdAt: "asc" },
  });

  // Serialize Decimal → number trước khi truyền xuống client
  const serializedWallets = wallets.map((w) => ({
    ...w,
    balance: Number(w.balance),
  }));

  return <WalletsClient initialWallets={serializedWallets} />;
}
```

**Tạo `src/app/(dashboard)/wallets/wallets-client.tsx`:**

```typescript
"use client";

// Toàn bộ phần client UI và event handlers giữ nguyên
// Chỉ thay đổi: nhận initialWallets prop thay vì fetch trong useEffect

type WalletItem = {
  id: string;
  name: string;
  balance: number;
  icon?: string | null;
};

export function WalletsClient({ initialWallets }: { initialWallets: WalletItem[] }) {
  const [wallets, setWallets] = useState<WalletItem[]>(initialWallets);
  // Xóa bỏ: isLoading state, fetchWallets(), useEffect để fetch ban đầu
  
  // Giữ lại fetchWallets chỉ để refresh sau mutation:
  const refreshWallets = async () => {
    const data = await getFormOptions();
    setWallets(data.wallets.map((w) => ({ ...w, balance: Number(w.balance) })));
  };

  // handleSubmit và handleDelete gọi refreshWallets() sau khi thành công
  // ... phần còn lại của component giữ nguyên
}
```

---

## PHẦN 5 — UI/UX & HIỆU NĂNG

### 5.1 — Fix Animation Delays quá cao

**Vấn đề:** Delay lũy tiến lên đến 800ms gây nội dung ẩn quá lâu sau khi đã load xong. Nguyên tắc: tổng thời gian animation không nên vượt quá 400ms.

**Sửa `src/components/fade-in.tsx`:**

```typescript
"use client";

import { motion } from "framer-motion";

interface FadeInProps {
  children: React.ReactNode;
  delay?: number;
  direction?: "up" | "down" | "left" | "right";
  className?: string; // Thêm className prop để linh hoạt hơn
}

export function FadeIn({
  children,
  delay = 0,
  direction = "up",
  className,
}: FadeInProps) {
  const offset = 12; // Giảm từ 20 → 12 để animation gọn hơn

  const directionMap = {
    up: { y: offset },
    down: { y: -offset },
    left: { x: offset },
    right: { x: -offset },
  };

  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, ...directionMap[direction] }}
      animate={{ opacity: 1, x: 0, y: 0 }} // Dùng animate thay vì whileInView
      transition={{
        duration: 0.35,    // Giảm từ 0.6 → 0.35
        delay: Math.min(delay, 0.3), // CAP delay tối đa 300ms
        ease: [0.21, 0.47, 0.32, 0.98],
      }}
    >
      {children}
    </motion.div>
  );
}
```

**Cập nhật delays trong `dashboard/page.tsx`:**

```typescript
// TRƯỚC: delay từ 0.1 → 0.8
// SAU: delay từ 0.05 → 0.25 (tổng max 250ms)
<FadeIn delay={0.05}> ... </FadeIn>
<FadeIn delay={0.1}> ... </FadeIn>
<FadeIn delay={0.15}> ... </FadeIn>
<FadeIn delay={0.2}> ... </FadeIn>
<FadeIn delay={0.25}> ... </FadeIn>
```

---

### 5.2 — Fix `DialogTrigger render={}` sai API

**Vấn đề:** Codebase dùng `render={<Button />}` prop của `@base-ui/react` nhưng đang import từ shadcn/ui (Radix). Đây là bug không chạy được đúng trên một số môi trường.

**Tìm và thay thế toàn bộ:**

```bash
# Tìm tất cả file dùng render prop sai
grep -r "DialogTrigger render=" src/
grep -r "DropdownMenuTrigger render=" src/
grep -r "AlertDialogTrigger render=" src/
```

**Sửa pattern:**

```tsx
// TRƯỚC (sai API):
<DialogTrigger render={<Button className="..." size="icon" />}>
  <Plus className="h-6 w-6" />
</DialogTrigger>

// SAU (đúng Radix/Shadcn):
<DialogTrigger asChild>
  <Button className="..." size="icon">
    <Plus className="h-6 w-6" />
  </Button>
</DialogTrigger>

// DropdownMenuTrigger:
<DropdownMenuTrigger asChild>
  <Button variant="ghost" size="icon" className="h-8 w-8 rounded-full">
    <MoreVertical className="h-4 w-4" />
  </Button>
</DropdownMenuTrigger>

// AlertDialogTrigger:
<AlertDialogTrigger asChild>
  <DropdownMenuItem
    onSelect={(e) => e.preventDefault()}
    className="text-destructive cursor-pointer"
  >
    <Trash2 className="mr-2 h-4 w-4" /> Xóa
  </DropdownMenuItem>
</AlertDialogTrigger>
```

**Xóa `@base-ui/react` khỏi `package.json`** vì không dùng nữa:

```bash
npm uninstall @base-ui/react
```

---

### 5.3 — Thêm PWA Offline Page

**Tạo `public/offline.html`:**

```html
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Không có kết nối — Quản lý Chi tiêu</title>
  <style>
    body {
      font-family: system-ui, sans-serif;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      background: #f8fafc;
      color: #1e293b;
      text-align: center;
      padding: 1rem;
    }
    h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
    p { color: #64748b; margin-bottom: 1.5rem; }
    button {
      background: #10b981;
      color: white;
      border: none;
      padding: 0.75rem 1.5rem;
      border-radius: 9999px;
      cursor: pointer;
      font-size: 1rem;
    }
  </style>
</head>
<body>
  <h1>Không có kết nối mạng</h1>
  <p>Vui lòng kiểm tra kết nối internet và thử lại.</p>
  <button onclick="window.location.reload()">Thử lại</button>
</body>
</html>
```

**Cập nhật `next.config.js`:**

```javascript
const withPWA = require("next-pwa")({
  dest: "public",
  disable: process.env.NODE_ENV === "development",
  register: true,
  skipWaiting: true,
  fallbacks: {
    document: "/offline.html", // Trang fallback khi offline
  },
});
```

---

## PHẦN 6 — BẢO MẬT BỔ SUNG

### 6.1 — Thêm `.env` vào `.gitignore`

Mở `.gitignore` và đảm bảo có:

```gitignore
# Environment variables — KHÔNG BAO GIỜ commit
.env
.env.local
.env.*.local
.env.production
```

### 6.2 — Thêm Rate Limiting cho AI endpoint

**Cài package:**
```bash
npm install @upstash/ratelimit @upstash/redis
```

**Hoặc nếu không muốn dùng Upstash, dùng in-memory đơn giản:**

```typescript
// src/app/api/ai/analyze/route.ts

// Map lưu timestamp lần cuối gọi AI, key = userId
const rateLimitMap = new Map<string, number>();
const RATE_LIMIT_MS = 60_000; // 1 phút mỗi user

export async function GET() {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // Rate limiting đơn giản
  const lastCall = rateLimitMap.get(session.user.id);
  if (lastCall && Date.now() - lastCall < RATE_LIMIT_MS) {
    const waitSeconds = Math.ceil((RATE_LIMIT_MS - (Date.now() - lastCall)) / 1000);
    return NextResponse.json(
      { error: `Vui lòng chờ ${waitSeconds}s trước khi phân tích lại.` },
      { status: 429 }
    );
  }
  rateLimitMap.set(session.user.id, Date.now());

  // ... phần còn lại giữ nguyên
}
```

> **Lưu ý:** In-memory rate limit sẽ reset khi server restart. Trong production thực sự, dùng Redis (Upstash) để persist state.

---

## PHẦN 7 — NÂNG CẤP DEPENDENCIES

### 7.1 — Thay thế `xlsx` bằng `exceljs`

```bash
npm uninstall xlsx
npm install exceljs
```

**Cập nhật `report-actions.ts`:**

```typescript
import ExcelJS from "exceljs";

export async function exportTransactionsToExcel() {
  try {
    const session = await auth();
    if (!session?.user?.id) throw new Error("Unauthorized");
    const userId = session.user.id;

    const transactions = await prisma.transaction.findMany({
      where: { userId },
      include: { wallet: true, toWallet: true, category: true },
      orderBy: { date: "desc" },
      // Thêm giới hạn để tránh OOM với dataset lớn
      take: 10_000,
    });

    const workbook = new ExcelJS.Workbook();
    workbook.creator = "Quản lý Chi tiêu App";
    const sheet = workbook.addWorksheet("Giao dịch");

    // Định nghĩa columns với type
    sheet.columns = [
      { header: "Ngày", key: "date", width: 15 },
      { header: "Loại", key: "type", width: 15 },
      { header: "Danh mục", key: "category", width: 20 },
      { header: "Ví/Nguồn", key: "wallet", width: 20 },
      { header: "Đến ví", key: "toWallet", width: 20 },
      { header: "Số tiền", key: "amount", width: 18, style: { numFmt: '#,##0' } },
      { header: "Ghi chú", key: "note", width: 30 },
    ];

    // Style header row
    sheet.getRow(1).font = { bold: true };
    sheet.getRow(1).fill = {
      type: "pattern",
      pattern: "solid",
      fgColor: { argb: "FF10B981" },
    };

    transactions.forEach((t) => {
      sheet.addRow({
        date: new Date(t.date).toLocaleDateString("vi-VN"),
        type: t.type === "INCOME" ? "Thu nhập" : t.type === "EXPENSE" ? "Chi tiêu" : "Chuyển tiền",
        category: t.category?.name || (t.type === "TRANSFER" ? "Chuyển khoản" : "N/A"),
        wallet: t.wallet.name,
        toWallet: t.toWallet?.name || "",
        amount: Number(t.amount),
        note: t.note || "",
      });
    });

    // Xuất buffer
    const buffer = await workbook.xlsx.writeBuffer();
    const base64 = Buffer.from(buffer).toString("base64");

    return { success: true, data: base64 };
  } catch (error) {
    if (error instanceof Error) console.error("Export Error:", error.message);
    return { success: false, error: "Không thể xuất file Excel" };
  }
}
```

---

## Thứ tự thực hiện khuyến nghị

Thực hiện theo thứ tự này để tránh xung đột và test từng bước:

```
Ngày 1 — Critical Fixes:
  ✅ 1.1 Fix middleware (auth.config.ts + middleware.ts)
  ✅ 1.2 Fix deleteWallet userId filter
  ✅ 2.1 Schema migration + Fix SavingGoal desync

Ngày 2 — Code Quality:
  ✅ 3.1 Tạo lib/utils.ts với formatCurrency
  ✅ 3.4 Thay alert() bằng sonner
  ✅ 3.5 Xóa get-categories.ts
  ✅ 3.2 Chuẩn hóa error handling (ActionResult type)

Ngày 3 — Architecture:
  ✅ 4.1 Fix double auth() call
  ✅ 4.3 Fix revalidatePath scope
  ✅ 4.4 Refactor WalletsPage → Server Component

Ngày 4 — TypeScript & UI:
  ✅ 3.3 Loại bỏ any, thêm Prisma types
  ✅ 5.2 Fix DialogTrigger render → asChild
  ✅ 5.1 Fix animation delays

Ngày 5 — Bổ sung & nâng cấp:
  ✅ 1.3 Fix updateProfile email uniqueness
  ✅ 4.2 Thêm error.tsx + loading.tsx
  ✅ 5.3 Thêm offline.html cho PWA
  ✅ 6.1 Fix .gitignore
  ✅ 6.2 Rate limiting AI endpoint
  ✅ 7.1 Upgrade xlsx → exceljs
  ✅ 2.2 Fix getCashFlowTrend dùng $queryRaw
```

---

## Checklist kiểm tra cuối cùng

Sau khi thực hiện toàn bộ, kiểm tra các điểm sau:

```bash
# 1. TypeScript không còn lỗi nào
npx tsc --noEmit

# 2. ESLint không còn any warnings
npx eslint src/ --ext .ts,.tsx

# 3. Build thành công
npm run build

# 4. Kiểm tra middleware hoạt động
# Mở incognito → truy cập /wallets → phải redirect về /login

# 5. Test SavingGoal desync fix
# Nạp tiền → xóa transaction → kiểm tra currentAmount được trừ lại

# 6. Test deleteWallet security
# Tạo ví → tạo transaction → thử xóa ví → phải bị chặn

# 7. Kiểm tra không còn alert() nào
grep -r "alert(" src/ --include="*.tsx" --include="*.ts"
# Kết quả mong đợi: (trống)

# 8. Kiểm tra không còn `any` không cần thiết
grep -rn "as any" src/ --include="*.tsx" --include="*.ts"
# Kết quả mong đợi: (trống)
```
