import { NextResponse, type NextRequest } from "next/server";

// Redirect to /login when there is no session cookie (the core still checks the JWT on every call).
export function middleware(req: NextRequest) {
  if (!req.cookies.has("dsoc_session")) {
    return NextResponse.redirect(new URL("/login", req.url));
  }
  return NextResponse.next();
}

export const config = { matcher: ["/((?!login|api|_next|favicon.ico).*)"] };
