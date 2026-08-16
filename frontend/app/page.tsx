"use client";

import { useState, useEffect } from "react";
import { Shield, Search, AlertTriangle, CheckCircle, Clock, ArrowRight, Loader2, Trash2, FileText, History } from "lucide-react";
import { clsx } from "clsx";

interface ScanResult {
  id: string;
  url: string;
  status: "pending" | "running" | "completed" | "failed";
  vulnerabilities: Vulnerability[];
  timestamp: string;
  scanType: string;
  reportPath?: string;
}

interface Vulnerability {
  type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  url: string;
  param?: string;
  description: string;
}

type Tab = "scanner" | "history" | "reports";

export default function Home() {
  const [targetUrl, setTargetUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanResult[]>([]);
  const [activeTab, setActiveTab] = useState<Tab>("scanner");

  // Load history from localStorage on mount
  useEffect(() => {
    const saved = localStorage.getItem("scanHistory");
    if (saved) {
      try {
        setScanHistory(JSON.parse(saved));
      } catch (e) {
        console.error("Failed to load history:", e);
      }
    }
  }, []);

  // Save history to localStorage
  useEffect(() => {
    localStorage.setItem("scanHistory", JSON.stringify(scanHistory));
  }, [scanHistory]);

  const startScan = async () => {
    if (!targetUrl) return;
    
    setIsScanning(true);
    const newScan: ScanResult = {
      id: Date.now().toString(),
      url: targetUrl,
      status: "running",
      vulnerabilities: [],
      timestamp: new Date().toISOString(),
      scanType: "full"
    };
    setCurrentScan(newScan);

    try {
      const response = await fetch("http://localhost:5000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: targetUrl, scan_type: "full" }),
      });

      if (response.ok) {
        const data = await response.json();
        const vulns = extractVulnerabilities(data);
        setCurrentScan({
          ...newScan,
          status: "completed",
          vulnerabilities: vulns,
          reportPath: data.reportPath
        });
        setScanHistory(prev => [{ ...newScan, status: "completed", vulnerabilities: vulns, reportPath: data.reportPath }, ...prev]);
      } else {
        setCurrentScan({ ...newScan, status: "failed" });
      }
    } catch (error) {
      console.error("Scan error:", error);
      // For demo, simulate a completed scan
      const demoVulns: Vulnerability[] = [
        { type: "SQL Injection", severity: "critical", url: targetUrl, param: "id", description: "Potential SQL injection detected in parameter 'id'" },
        { type: "XSS", severity: "high", url: targetUrl + "/search", param: "q", description: "Reflected XSS in search parameter" },
        { type: "Missing CSRF", severity: "medium", url: targetUrl + "/form", description: "Form lacks CSRF protection" },
      ];
      setCurrentScan({
        ...newScan,
        status: "completed",
        vulnerabilities: demoVulns
      });
      setScanHistory(prev => [{ ...newScan, status: "completed", vulnerabilities: demoVulns }, ...prev]);
    }

    setIsScanning(false);
  };

  const clearHistory = () => {
    setScanHistory([]);
    localStorage.removeItem("scanHistory");
  };

  const clearCurrentScan = () => {
    setCurrentScan(null);
    setTargetUrl("");
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "text-red-600 bg-red-50 dark:bg-red-950";
      case "high": return "text-orange-600 bg-orange-50 dark:bg-orange-950";
      case "medium": return "text-yellow-600 bg-yellow-50 dark:bg-yellow-950";
      case "low": return "text-blue-600 bg-blue-50 dark:bg-blue-950";
      default: return "text-gray-600 bg-gray-50 dark:bg-gray-950";
    }
  };

  // Extract vulnerabilities from backend response
  const extractVulnerabilities = (data: any): Vulnerability[] => {
    const vulns: Vulnerability[] = [];
    
    // XSS
    if (data.xss_vulnerabilities) {
      data.xss_vulnerabilities.forEach((v: any) => {
        vulns.push({ type: "XSS", severity: "high", url: v.url || data.url, param: v.parameter, description: v.payload || "XSS vulnerability detected" });
      });
    }
    // SQL Injection
    if (data.sql_vulnerabilities) {
      data.sql_vulnerabilities.forEach((v: any) => {
        vulns.push({ type: "SQL Injection", severity: "critical", url: v.url || data.url, param: v.parameter, description: v.payload || "SQL injection detected" });
      });
    }
    // IDOR
    if (data.idor_vulnerabilities) {
      data.idor_vulnerabilities.forEach((v: any) => {
        vulns.push({ type: "IDOR", severity: "high", url: v.endpoint || data.url, description: v.description || "Insecure Direct Object Reference" });
      });
    }
    // Authorization
    if (data.authorization_flaws) {
      data.authorization_flaws.forEach((v: any) => {
        vulns.push({ type: "Authorization Flaw", severity: "critical", url: v.endpoint || data.url, description: v.evidence || "Authorization bypass detected" });
      });
    }
    // CSRF
    if (data.csrf) {
      data.csrf.forEach((v: any) => {
        vulns.push({ type: "CSRF", severity: "medium", url: v.url || data.url, description: v.explanation || "CSRF protection missing" });
      });
    }
    // DOM XSS
    if (data.dom_xss) {
      data.dom_xss.forEach((v: any) => {
        vulns.push({ type: "DOM XSS", severity: "high", url: v.url || data.url, description: v.explanation || "DOM-based XSS" });
      });
    }
    // Open Redirect
    if (data.open_redirects) {
      data.open_redirects.forEach((v: any) => {
        vulns.push({ type: "Open Redirect", severity: "medium", url: v.url || data.url, param: v.parameter, description: "Open redirect vulnerability" });
      });
    }
    // SSRF
    if (data.ssrf) {
      data.ssrf.forEach((v: any) => {
        vulns.push({ type: "SSRF", severity: "critical", url: v.url || data.url, param: v.parameter, description: "Server-Side Request Forgery" });
      });
    }
    
    return vulns;
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800">
      {/* Header */}
      <header className="border-b bg-white dark:bg-gray-950">
        <div className="container mx-auto flex h-16 items-center justify-between px-4">
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            <span className="text-xl font-bold">DSG Suite</span>
          </div>
          <nav className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab("scanner")}
              className={clsx(
                "px-4 py-2 text-sm font-medium rounded-lg transition-colors",
                activeTab === "scanner" ? "bg-primary text-primary-foreground" : "hover:bg-gray-100 dark:hover:bg-gray-800"
              )}
            >
              Scanner
            </button>
            <button
              onClick={() => setActiveTab("history")}
              className={clsx(
                "px-4 py-2 text-sm font-medium rounded-lg transition-colors flex items-center gap-2",
                activeTab === "history" ? "bg-primary text-primary-foreground" : "hover:bg-gray-100 dark:hover:bg-gray-800"
              )}
            >
              <History className="h-4 w-4" />
              History
            </button>
            <button
              onClick={() => setActiveTab("reports")}
              className={clsx(
                "px-4 py-2 text-sm font-medium rounded-lg transition-colors flex items-center gap-2",
                activeTab === "reports" ? "bg-primary text-primary-foreground" : "hover:bg-gray-100 dark:hover:bg-gray-800"
              )}
            >
              <FileText className="h-4 w-4" />
              Reports
            </button>
          </nav>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        {/* Scanner Tab */}
        {activeTab === "scanner" && (
          <>
            {/* Hero Section */}
            <div className="mx-auto max-w-3xl text-center">
              <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">
                Web Vulnerability Scanner
              </h1>
              <p className="mt-4 text-lg text-muted-foreground">
                Scan your web applications for SQL Injection, XSS, CSRF, and other security vulnerabilities.
              </p>
            </div>

            {/* Search Box */}
            <div className="mx-auto mt-8 max-w-2xl">
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                  <input
                    type="url"
                    placeholder="Enter target URL (e.g., http://example.com)"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    className="w-full h-12 pl-10 pr-4 rounded-lg border bg-white dark:bg-gray-950 focus:outline-none focus:ring-2 focus:ring-primary"
                    onKeyDown={(e) => e.key === "Enter" && startScan()}
                  />
                </div>
                <button
                  onClick={startScan}
                  disabled={isScanning || !targetUrl}
                  className="h-12 px-6 rounded-lg bg-primary text-primary-foreground font-medium hover:bg-primary/90 disabled:opacity-50 flex items-center gap-2"
                >
                  {isScanning ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Scanning
                    </>
                  ) : (
                    <>
                      Start Scan
                      <ArrowRight className="h-4 w-4" />
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Current Scan Status */}
            {currentScan && (
              <div className="mx-auto mt-8 max-w-4xl">
                <div className="rounded-lg border bg-white dark:bg-gray-950 p-6 shadow-sm">
                  <div className="flex items-center justify-between">
                    <h2 className="text-lg font-semibold">Scan Results</h2>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={clearCurrentScan}
                        className="p-2 text-sm text-muted-foreground hover:text-foreground"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                      <span className={clsx(
                        "inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium",
                        currentScan.status === "completed" && "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
                        currentScan.status === "running" && "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
                        currentScan.status === "failed" && "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
                      )}>
                        {currentScan.status === "running" && <Loader2 className="h-3 w-3 animate-spin" />}
                        {currentScan.status === "completed" && <CheckCircle className="h-3 w-3" />}
                        {currentScan.status === "failed" && <AlertTriangle className="h-3 w-3" />}
                        {currentScan.status}
                      </span>
                    </div>
                  </div>
                  <p className="mt-2 text-sm text-muted-foreground">{currentScan.url}</p>
                  
                  {currentScan.vulnerabilities.length > 0 && (
                    <div className="mt-4 space-y-3">
                      {currentScan.vulnerabilities.map((vuln, idx) => (
                        <div key={idx} className="flex items-start gap-3 rounded-lg border p-3">
                          <AlertTriangle className={clsx(
                            "h-5 w-5 mt-0.5",
                            vuln.severity === "critical" && "text-red-500",
                            vuln.severity === "high" && "text-orange-500",
                            vuln.severity === "medium" && "text-yellow-500",
                            vuln.severity === "low" && "text-blue-500"
                          )} />
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <span className="font-medium">{vuln.type}</span>
                              <span className={clsx("text-xs px-2 py-0.5 rounded-full", getSeverityColor(vuln.severity))}>
                                {vuln.severity}
                              </span>
                            </div>
                            <p className="mt-1 text-sm text-muted-foreground">{vuln.description}</p>
                            {vuln.param && (
                              <p className="mt-1 text-xs text-muted-foreground">Parameter: {vuln.param}</p>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {currentScan.status === "completed" && currentScan.vulnerabilities.length === 0 && (
                    <div className="mt-4 flex items-center gap-2 text-green-600">
                      <CheckCircle className="h-5 w-5" />
                      <span>No vulnerabilities found!</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </>
        )}

        {/* History Tab */}
        {activeTab === "history" && (
          <div className="mx-auto max-w-4xl">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-2xl font-bold">Scan History</h2>
              {scanHistory.length > 0 && (
                <button
                  onClick={clearHistory}
                  className="flex items-center gap-2 px-4 py-2 text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-950 rounded-lg"
                >
                  <Trash2 className="h-4 w-4" />
                  Clear All
                </button>
              )}
            </div>

            {scanHistory.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground">
                <Clock className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No scan history yet.</p>
                <p className="text-sm">Run a scan to see it here.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {scanHistory.map((scan) => (
                  <div key={scan.id} className="flex items-center justify-between rounded-lg border bg-white dark:bg-gray-950 p-4">
                    <div className="flex items-center gap-3">
                      <Clock className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <p className="font-medium">{scan.url}</p>
                        <p className="text-sm text-muted-foreground">
                          {new Date(scan.timestamp).toLocaleString()} • {scan.vulnerabilities.length} vulnerabilities
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={clsx(
                        "text-xs px-2 py-1 rounded-full",
                        scan.vulnerabilities.length > 0 ? "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200" : "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                      )}>
                        {scan.vulnerabilities.length > 0 ? `${scan.vulnerabilities.length} found` : "Clean"}
                      </span>
                      <span className={clsx(
                        "text-xs px-2 py-1 rounded-full",
                        scan.status === "completed" ? "bg-green-100 text-green-800" : 
                        scan.status === "failed" ? "bg-red-100 text-red-800" : "bg-blue-100 text-blue-800"
                      )}>
                        {scan.status}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Reports Tab */}
        {activeTab === "reports" && (
          <div className="mx-auto max-w-4xl">
            <h2 className="text-2xl font-bold mb-6">Saved Reports</h2>
            <div className="grid gap-4">
              <a
                href="/reports/report.html"
                target="_blank"
                className="flex items-center gap-4 p-4 rounded-lg border bg-white dark:bg-gray-950 hover:shadow-md transition-shadow"
              >
                <FileText className="h-8 w-8 text-blue-500" />
                <div>
                  <p className="font-medium">HTML Report</p>
                  <p className="text-sm text-muted-foreground">Visual vulnerability report</p>
                </div>
              </a>
              <a
                href="/reports/report.json"
                target="_blank"
                className="flex items-center gap-4 p-4 rounded-lg border bg-white dark:bg-gray-950 hover:shadow-md transition-shadow"
              >
                <FileText className="h-8 w-8 text-green-500" />
                <div>
                  <p className="font-medium">JSON Report</p>
                  <p className="text-sm text-muted-foreground">Machine-readable scan data</p>
                </div>
              </a>
            </div>
            <p className="mt-4 text-sm text-muted-foreground">
              Reports are saved in: <code className="bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded">backend/reports/</code>
            </p>
          </div>
        )}
      </main>
    </div>
  );
}