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