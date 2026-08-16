import type { Metadata } from "next";
import "./globals.css";
import { clsx } from "clsx";

export const metadata: Metadata = {
  title: "DSG Suite - Vulnerability Scanner",
  description: "Web Application Vulnerability Scanner",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={clsx("min-h-screen bg-background font-sans antialiased")}>
        {children}
      </body>
    </html>
  );
}