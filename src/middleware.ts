import { auth } from '@/lib/auth';

export default auth;

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