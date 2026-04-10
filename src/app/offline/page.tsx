import Link from "next/link";

export default function OfflinePage() {
  return (
    <main className="grid min-h-screen place-items-center bg-slate-950 text-white px-6 py-16 text-center">
      <div className="max-w-xl rounded-3xl border border-white/10 bg-slate-900/90 p-10 shadow-2xl shadow-slate-950/40">
        <h1 className="text-4xl font-semibold tracking-tight">Không có kết nối mạng</h1>
        <p className="mt-4 text-lg leading-8 text-slate-300">
          Ứng dụng đang ở chế độ offline. Vui lòng kiểm tra kết nối hoặc thử lại sau.
        </p>
        <div className="mt-8 flex justify-center gap-4">
          <Link
            href="/"
            className="rounded-full bg-emerald-500 px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-emerald-400"
          >
            Về trang chủ
          </Link>
        </div>
      </div>
    </main>
  );
}
