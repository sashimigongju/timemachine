import "dotenv/config";
import express from "express";
import { randomUUID } from "node:crypto";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { Readability } from "@mozilla/readability";
import { JSDOM } from "jsdom";

const app = express();
const PORT = process.env.PORT || 3000;
const BRAVE_API_KEY = process.env.BRAVE_API_KEY;
const EXA_API_KEY = process.env.EXA_API_KEY;

if (!BRAVE_API_KEY) {
  throw new Error("BRAVE_API_KEY를 .env 파일에 설정하세요.");
}

if (!EXA_API_KEY) {
  console.warn("EXA_API_KEY가 설정되지 않았습니다. Exa 검색은 사용할 수 없습니다.");
}

app.use(express.json({ limit: "20kb" }));
app.use(express.static("public"));

// 검색 결과를 임시 보관합니다. 원문 요청은 임의 URL 대신 이 ID로 받습니다.
const resultCache = new Map();

function parseDate(value) {
  if (!value) return null;

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;

  return date.toISOString().slice(0, 10);
}

function isInRange(date, start, end) {
  return Boolean(date && date >= start && date <= end);
}

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(n => n < 0 || n > 255)) return true;

  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224
  );
}

function isPrivateIPv6(ip) {
  const normalized = ip.toLowerCase();
  return (
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:") ||
    normalized.startsWith("::ffff:127.") ||
    normalized.startsWith("::ffff:10.") ||
    normalized.startsWith("::ffff:192.168.")
  );
}

// 원문 추출 기능의 기본 안전 검사입니다.
// 실제 서비스 배포 전에는 서버의 outbound 방화벽 등 추가 SSRF 방어도 적용하세요.
async function assertPublicHttpUrl(rawUrl) {
  const url = new URL(rawUrl);

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("HTTP 또는 HTTPS 주소만 허용됩니다.");
  }

  const hostname = url.hostname.toLowerCase();

  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local")
  ) {
    throw new Error("허용되지 않는 주소입니다.");
  }

  const ipType = isIP(hostname);

  if (ipType === 4 && isPrivateIPv4(hostname)) {
    throw new Error("사설 IP 주소는 허용되지 않습니다.");
  }

  if (ipType === 6 && isPrivateIPv6(hostname)) {
    throw new Error("사설 IP 주소는 허용되지 않습니다.");
  }

  if (!ipType) {
    const addresses = await lookup(hostname, { all: true });

    if (
      addresses.length === 0 ||
      addresses.some(({ address }) => {
        const type = isIP(address);
        return (
          (type === 4 && isPrivateIPv4(address)) ||
          (type === 6 && isPrivateIPv6(address))
        );
      })
    ) {
      throw new Error("접속할 수 없는 주소입니다.");
    }
  }

  return url;
}

function findPublishedDate(document) {
  const candidates = [];

  // 기사에 명시된 게시일 메타데이터
  const metaSelectors = [
    'meta[property="article:published_time"]',
    'meta[name="datePublished"]',
    'meta[itemprop="datePublished"]',
    'meta[property="og:published_time"]'
  ];

  for (const selector of metaSelectors) {
    const value = document.querySelector(selector)?.content;
    if (value) candidates.push(value);
  }

  const timeValue = document
    .querySelector('time[datetime], time[itemprop="datePublished"]')
    ?.getAttribute("datetime");

  if (timeValue) candidates.push(timeValue);

  // JSON-LD에서 datePublished를 찾습니다.
  for (const script of document.querySelectorAll(
    'script[type="application/ld+json"]'
  )) {
    try {
      const json = JSON.parse(script.textContent);

      const visit = value => {
        if (Array.isArray(value)) {
          value.forEach(visit);
        } else if (value && typeof value === "object") {
          if (typeof value.datePublished === "string") {
            candidates.push(value.datePublished);
          }
          Object.values(value).forEach(visit);
        }
      };

      visit(json);
    } catch {
      // 잘못된 JSON-LD는 건너뜁니다.
    }
  }

  for (const candidate of candidates) {
    const parsed = parseDate(candidate);
    if (parsed) return parsed;
  }

  return null;
}

async function searchExa(query, year) {
  if (!EXA_API_KEY) {
    throw new Error("EXA_API_KEY가 설정되지 않았습니다.");
  }

  const response = await fetch("https://api.exa.ai/search", {
    method: "POST",
    headers: {
      "x-api-key": EXA_API_KEY,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      query,
      type: "auto",
      numResults: 100,
      startPublishedDate: `${year - 1}-12-31T23:59:59.999Z`,
      endPublishedDate: `${year + 1}-01-01T00:00:00.000Z`
    }),
    signal: AbortSignal.timeout(15000)
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || `Exa API 오류: ${response.status}`);
  }

  return data;
}

app.get("/api/search", async (req, res) => {
  try {
    const query = String(req.query.q ?? "").trim();
    const year = Number(req.query.year);
    const offset = Number(req.query.offset ?? 0);
    const platform = String(req.query.platform ?? "all");
    const siteFilters = {
      all: "",
      facebook: "site:facebook.com",
      dcinside: "site:dcinside.com"
    };

    if (!Number.isInteger(offset) || offset < 0 || offset > 9) {
      return res.status(400).json({ error: "페이지 번호를 확인해 주세요." });
    }

    if (!Object.hasOwn(siteFilters, platform)) {
      return res.status(400).json({ error: "검색 대상을 확인해 주세요." });
    }

    if (!query) {
      return res.status(400).json({ error: "검색어를 입력해 주세요." });
    }

    if (!Number.isInteger(year) || year < 1990 || year > 2100) {
      return res.status(400).json({ error: "연도를 확인해 주세요." });
    }

    const start = `${year}-01-01`;
    const end = `${year}-12-31`;
    const searchQuery = [siteFilters[platform], query].filter(Boolean).join(" ");

    async function searchBrave() {
      const url = new URL("https://api.search.brave.com/res/v1/web/search");
      url.searchParams.set("q", searchQuery);
      url.searchParams.set("country", "KR");
      url.searchParams.set("search_lang", "ko");
      url.searchParams.set("count", "20");
      url.searchParams.set("offset", String(offset));
      url.searchParams.set("freshness", `${start}to${end}`);
      url.searchParams.set("result_filter", "web");
      url.searchParams.set("spellcheck", "false");
      url.searchParams.set("summary", "false");
      url.searchParams.set("enable_rich_callback", "false");

      const response = await fetch(url, {
        headers: {
          "X-Subscription-Token": BRAVE_API_KEY,
          "Accept": "application/json"
        },
        signal: AbortSignal.timeout(15000)
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error?.detail || `Brave API 오류: ${response.status}`);
      }

      return data;
    }

    const requests = [
      searchBrave().then(data => ({ provider: "Brave", data }))
    ];

    if (offset === 0) {
      requests.push(
        searchExa(searchQuery, year).then(data => ({ provider: "Exa", data }))
      );
    }

    const settled = await Promise.allSettled(requests);
    const candidates = [];
    const sourceErrors = [];
    let succeededSources = 0;
    let braveHasMore = false;

    for (const item of settled) {
      if (item.status === "rejected") {
        const message = item.reason?.message || "검색 서비스 오류";
        sourceErrors.push(message);
        console.error(message);
        continue;
      }

      succeededSources += 1;
      const { provider, data } = item.value;

      if (provider === "Brave") {
        braveHasMore = Boolean(data.query?.more_results_available);
        for (const result of data.web?.results ?? []) {
          candidates.push({
            provider,
            title: result.title ?? "",
            url: result.url,
            dateValue: result.page_age,
            snippet: result.description ?? ""
          });
        }
      } else {
        for (const result of data.results ?? []) {
          candidates.push({
            provider,
            title: result.title ?? "",
            url: result.url,
            dateValue: result.publishedDate,
            snippet: ""
          });
        }
      }
    }

    if (succeededSources === 0) {
      return res.status(502).json({
        error: "검색 API 요청이 모두 실패했습니다.",
        sourceErrors
      });
    }

    const results = [];
    const seen = new Map();
    let omittedOutsideYear = 0;

    for (const item of candidates) {
      if (!item.url) continue;

      const pageDate = parseDate(item.dateValue);
      if (pageDate && !isInRange(pageDate, start, end)) {
        omittedOutsideYear += 1;
        continue;
      }

      let normalizedUrl = item.url;
      try {
        const parsedUrl = new URL(item.url);
        parsedUrl.hash = "";
        for (const key of [...parsedUrl.searchParams.keys()]) {
          if (/^(utm_.+|fbclid|gclid)$/i.test(key)) {
            parsedUrl.searchParams.delete(key);
          }
        }
        normalizedUrl = parsedUrl.toString().replace(/\/$/, "");
      } catch {
        // Keep the provider URL if it cannot be normalized.
      }

      if (seen.has(normalizedUrl)) {
        const existing = results[seen.get(normalizedUrl)];
        if (!existing.providers.includes(item.provider)) {
          existing.providers.push(item.provider);
        }
        if (!existing.snippet && item.snippet) {
          existing.snippet = item.snippet;
        }
        if (!existing.date && pageDate) {
          existing.date = pageDate;
        }
        continue;
      }

      const id = randomUUID();
      resultCache.set(id, {
        url: item.url,
        title: item.title,
        pageDate,
        start,
        end
      });

      seen.set(normalizedUrl, results.length);
      results.push({
        id,
        title: item.title,
        url: item.url,
        date: pageDate,
        snippet: item.snippet,
        providers: [item.provider]
      });
    }

    results.sort((a, b) => {
      if (!a.date) return b.date ? 1 : 0;
      if (!b.date) return -1;
      return b.date.localeCompare(a.date);
    });

    // 임시 저장 정보가 무한히 쌓이지 않도록 오래된 항목을 정리합니다.
    if (resultCache.size > 500) {
      resultCache.clear();
    }

    res.json({
      year,
      offset,
      platform,
      results,
      hasMore: braveHasMore && offset < 9,
      omittedOutsideYear,
      sourceErrors
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "검색 중 오류가 발생했습니다." });
  }
});

app.get("/api/article/:id", async (req, res) => {
  try {
    const cached = resultCache.get(req.params.id);

    if (!cached) {
      return res.status(404).json({
        error: "검색 결과가 만료되었습니다. 다시 검색해 주세요."
      });
    }

    const url = await assertPublicHttpUrl(cached.url);

    // 외부 사이트의 리다이렉트는 따라가지 않습니다.
    const response = await fetch(url, {
      headers: {
        "User-Agent": "YearSearchDemo/1.0",
        "Accept": "text/html"
      },
      redirect: "error",
      signal: AbortSignal.timeout(12000)
    });

    const contentType = response.headers.get("content-type") ?? "";

    if (!contentType.includes("text/html")) {
      return res.status(415).json({
        error: "이 주소는 HTML 게시글이 아니어서 본문을 추출할 수 없습니다."
      });
    }

    const buffer = await response.arrayBuffer();

    if (buffer.byteLength > 2_000_000) {
      return res.status(413).json({ error: "페이지가 너무 큽니다." });
    }

    const html = new TextDecoder("utf-8").decode(buffer);
    const dom = new JSDOM(html, { url: url.href });
    const publishedDate = findPublishedDate(dom.window.document);

    // 실제 게시일을 알아낼 수 있는 경우에만 원문을 보여주는 엄격 모드입니다.
    if (!publishedDate) {
      return res.status(422).json({
        error: "원문 페이지에서 게시일을 확인하지 못해 엄격 모드에서 제외했습니다."
      });
    }

    if (!isInRange(publishedDate, cached.start, cached.end)) {
      return res.status(422).json({
        error: `원문 게시일(${publishedDate})이 선택한 연도 범위 밖입니다.`
      });
    }

    const article = new Readability(dom.window.document).parse();

    if (!article?.textContent?.trim()) {
      return res.status(422).json({
        error: "본문을 자동 추출할 수 없습니다. 원문 사이트에서 확인해 주세요."
      });
    }

    res.json({
      title: article.title || cached.title,
      url: url.href,
      publishedDate,
      text: article.textContent.trim()
    });

    dom.window.close();
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: "원문을 가져오지 못했습니다. 사이트 접근 제한 또는 네트워크 문제일 수 있습니다."
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`사이트 실행 중: ${PORT}`);
});
