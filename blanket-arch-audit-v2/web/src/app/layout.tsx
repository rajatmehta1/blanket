import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "BlanketAudit — AI Architecture Governance",
  description: "AI-powered architecture audit for security, compliance, and code quality.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="font-sans antialiased">{children}</body>
    </html>
  );
}
