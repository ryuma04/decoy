import Link from "next/link";

export default function NotFound() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-canvas p-6 text-center">
      <h2 className="text-3xl font-mono font-bold tracking-tight mb-2">404 - Page Not Found</h2>
      <p className="text-mute text-sm mb-6 max-w-md">
        The requested security resource or decoy route does not exist.
      </p>
      <Link
        href="/"
        className="px-4 py-2 rounded border border-hairline bg-elevated hover:bg-elevated/80 text-sm font-medium transition"
      >
        Return to Overview
      </Link>
    </div>
  );
}
