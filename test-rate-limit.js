require('dotenv').config();
const API_URL = process.env.API_URL;

const TOTAL_REQUESTS = 10_000;
const CONCURRENCY = 10;

if (!API_URL) {
  console.error("Set API_URL to your own backend URL.");
  process.exit(1);
}

const counts = {};
let completed = 0;
let failed = 0;
const latencies = [];

async function sendRequest() {
  const start = performance.now();

  try {
    const response = await fetch(`${API_URL}/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        usrname: "rate-limit-test-nonexistent-user",
        password: "invalid-test-password"
      }),
      signal: AbortSignal.timeout(15000)
    });

    counts[response.status] = (counts[response.status] || 0) + 1;
    latencies.push(performance.now() - start);

    // Consume the response body before continuing.
    await response.text();
  } catch (error) {
    failed++;
    console.error("Request failed:", error.message);
  }

  completed++;

  if (completed % 1000 === 0) {
    console.log(`Completed ${completed}/${TOTAL_REQUESTS}`);
  }
}

async function main() {
  console.log(`Target: ${API_URL}/login`);
  console.log(`Requests: ${TOTAL_REQUESTS}`);
  console.log(`Concurrency: ${CONCURRENCY}`);
  console.log("Starting test...");

  const testStart = performance.now();

  // Fixed-size batches limit concurrent requests.
  for (let i = 0; i < TOTAL_REQUESTS; i += CONCURRENCY) {
    const batchSize = Math.min(
      CONCURRENCY,
      TOTAL_REQUESTS - i
    );

    await Promise.all(
      Array.from({ length: batchSize }, () => sendRequest())
    );
  }

  const duration = (performance.now() - testStart) / 1000;
  latencies.sort((a, b) => a - b);

  const percentile = (p) => {
    if (latencies.length === 0) return 0;

    return latencies[
      Math.min(
        latencies.length - 1,
        Math.ceil(p * latencies.length) - 1
      )
    ];
  };

  console.log("\n===== RATE LIMIT TEST RESULTS =====");
  console.log(`Completed: ${completed}`);
  console.log(`Network/errors: ${failed}`);
  console.log(`Duration: ${duration.toFixed(2)} seconds`);
  console.log(`Throughput: ${(completed / duration).toFixed(2)} requests/sec`);
  console.log("\nHTTP status counts:");

  for (const [status, count] of Object.entries(counts).sort()) {
    console.log(`${status}: ${count}`);
  }

  console.log("\nLatency:");
  console.log(`p50: ${percentile(0.50).toFixed(2)} ms`);
  console.log(`p95: ${percentile(0.95).toFixed(2)} ms`);
  console.log(`p99: ${percentile(0.99).toFixed(2)} ms`);

  console.log("\nRate limiter observations:");

  const limited = counts[429] || 0;

  if (limited > 0) {
    console.log(`Rate limiter rejected ${limited} requests.`);
  } else {
    console.log("No HTTP 429 responses observed.");
    console.log("Investigate the limiter configuration if this is unexpected.");
  }
}

main().catch(console.error);
