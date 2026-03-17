const fs = require("fs");
const path = require("path");

const apacheLogPath = path.join(__dirname, "sample_logs", "apache_access.log");
const authLogPath = path.join(__dirname, "sample_logs", "auth.log");
const outputPath = path.join(__dirname, "output", "analysis.json");

function readFileLines(filePath) {
  if (!fs.existsSync(filePath)) {
    console.error(`Missing file: ${filePath}`);
    process.exit(1);
  }
  return fs.readFileSync(filePath, "utf8").split("\n").filter(Boolean);
}

function analyzeApacheLogs(lines) {
  const suspiciousPaths = [
    "/wp-login.php",
    "/admin",
    "/phpmyadmin",
    "/.env",
    "/etc/passwd"
  ];

  const suspiciousPatterns = [
    /union\s+select/i,
    /select.+from/i,
    /<script>/i,
    /\.\.\//,
    /cmd=/i
  ];

  const ipRequestCount = {};
  const suspiciousRequests = [];
  const uniqueIPs = new Set();

  for (const line of lines) {
    const ipMatch = line.match(/^(\d+\.\d+\.\d+\.\d+)/);
    const requestMatch = line.match(/"(GET|POST|HEAD)\s(.+?)\sHTTP\/[\d.]+"/);
    const statusMatch = line.match(/"\s(\d{3})\s/);

    if (!ipMatch || !requestMatch) continue;

    const ip = ipMatch[1];
    const method = requestMatch[1];
    const requestPath = requestMatch[2];
    const status = statusMatch ? statusMatch[1] : "unknown";

    uniqueIPs.add(ip);
    ipRequestCount[ip] = (ipRequestCount[ip] || 0) + 1;

    const pathFlag = suspiciousPaths.some((p) => requestPath.includes(p));
    const patternFlag = suspiciousPatterns.some((pattern) => pattern.test(requestPath));

    if (pathFlag || patternFlag || Number(status) >= 400) {
      suspiciousRequests.push({
        ip,
        method,
        requestPath,
        status
      });
    }
  }

  const highVolumeIPs = Object.entries(ipRequestCount)
    .filter(([, count]) => count >= 4)
    .map(([ip, count]) => ({ ip, count }));

  return {
    totalLines: lines.length,
    uniqueIPs: Array.from(uniqueIPs),
    highVolumeIPs,
    suspiciousRequests
  };
}

function analyzeAuthLogs(lines) {
  const failedLogins = {};
  const successfulLogins = [];
  const suspiciousSuccessAfterFailure = [];

  for (const line of lines) {
    const failedMatch = line.match(/Failed password for (invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)/);
    const successMatch = line.match(/Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)/);

    if (failedMatch) {
      const username = failedMatch[2];
      const ip = failedMatch[3];
      const key = `${ip}:${username}`;

      failedLogins[key] = (failedLogins[key] || 0) + 1;
    }

    if (successMatch) {
      const username = successMatch[1];
      const ip = successMatch[2];
      successfulLogins.push({ ip, username });

      const key = `${ip}:${username}`;
      if (failedLogins[key] && failedLogins[key] >= 3) {
        suspiciousSuccessAfterFailure.push({
          ip,
          username,
          priorFailures: failedLogins[key]
        });
      }
    }
  }

  const bruteForceCandidates = Object.entries(failedLogins)
    .filter(([, count]) => count >= 3)
    .map(([key, count]) => {
      const [ip, username] = key.split(":");
      return { ip, username, failedAttempts: count };
    });

  return {
    totalLines: lines.length,
    bruteForceCandidates,
    successfulLogins,
    suspiciousSuccessAfterFailure
  };
}

function buildIOCList(apacheAnalysis, authAnalysis) {
  const ipSet = new Set();

  apacheAnalysis.suspiciousRequests.forEach((entry) => ipSet.add(entry.ip));
  apacheAnalysis.highVolumeIPs.forEach((entry) => ipSet.add(entry.ip));
  authAnalysis.bruteForceCandidates.forEach((entry) => ipSet.add(entry.ip));
  authAnalysis.suspiciousSuccessAfterFailure.forEach((entry) => ipSet.add(entry.ip));

  return Array.from(ipSet);
}

function main() {
  const apacheLines = readFileLines(apacheLogPath);
  const authLines = readFileLines(authLogPath);

  const apacheAnalysis = analyzeApacheLogs(apacheLines);
  const authAnalysis = analyzeAuthLogs(authLines);
  const iocs = buildIOCList(apacheAnalysis, authAnalysis);

  const result = {
    summary: {
      project: "SOC Log Triage Casebook",
      generatedAt: new Date().toISOString(),
      totalSuspiciousIPs: iocs.length
    },
    apacheAnalysis,
    authAnalysis,
    iocs
  };

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(result, null, 2));

  console.log("Analysis complete.");
  console.log(`Suspicious IPs identified: ${iocs.length}`);
  console.log(`Output written to: ${outputPath}`);
}

main();
