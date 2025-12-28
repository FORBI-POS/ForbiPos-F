import axios, { AxiosRequestConfig } from "axios";
import { API_BASE_URL } from "@/utils/apiConfig";

const axiosInstance = axios.create({
  baseURL: API_BASE_URL ?? undefined,
  withCredentials: true,
});

function normalizeHeaders(headers: Headers | Record<string, any> | undefined) {
  const out: Record<string, string> = {};
  if (!headers) return out;
  if (typeof (headers as any).forEach === "function") {
    try {
      (headers as Headers).forEach((value, key) => {
        out[key] = value;
      });
    } catch (e) {
      // fallback
    }
  } else {
    for (const k of Object.keys(headers as Record<string, any>)) {
      const v = (headers as Record<string, any>)[k];
      out[k.toLowerCase()] = typeof v === "string" ? v : String(v);
    }
  }
  return out;
}

function toFetchLikeResponse(res: any) {
  return {
    ok: res.status >= 200 && res.status < 300,
    status: res.status,
    statusText: res.statusText,
    headers: new Headers(res.headers || {}),
    json: async () => res.data,
    text: async () => (typeof res.data === "string" ? res.data : JSON.stringify(res.data)),
  };
}

// Replace global fetch with an axios-backed implementation
;(window as any).fetch = async (input: RequestInfo, init?: RequestInit) => {
  const rawUrl = typeof input === "string" ? input : (input as Request).url;
  const method = (init?.method || "GET").toLowerCase();
  const headers = normalizeHeaders(init?.headers as Headers | Record<string, any> | undefined);

  const axiosConfig: AxiosRequestConfig = {
    method: method as any,
    headers,
    // allow axios to handle absolute URLs; if the request matches API_BASE_URL prefix, make it relative
    url: rawUrl.startsWith(API_BASE_URL ?? "") ? rawUrl.replace(API_BASE_URL ?? "", "") : rawUrl,
    responseType: (init && (init as any).responseType) || "json",
    signal: (init as any)?.signal,
  };

  if (init && init.body !== undefined && init.body !== null) {
    // If body is a string (likely JSON), try to parse it to pass to axios as data
    const body = init.body as any;
    if (typeof body === "string") {
      try {
        axiosConfig.data = JSON.parse(body);
      } catch (e) {
        axiosConfig.data = body;
      }
    } else {
      axiosConfig.data = body;
    }
  }

  try {
    const res = await axiosInstance.request(axiosConfig);
    return toFetchLikeResponse(res);
  } catch (error: any) {
    if (error && error.response) {
      return toFetchLikeResponse(error.response);
    }
    throw error;
  }
};

export default axiosInstance;
