const axios = require("axios");
const { env } = require("../config");
const logger = require("../logger");

const client = axios.create({
  baseURL: env.BACKEND_URL,
  timeout: env.BACKEND_REQUEST_TIMEOUT_MS,
  headers: { Accept: "application/json" },
  validateStatus: (status) => status < 500,
});

client.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response) {
      logger.warn(
        { status: err.response.status, url: err.config?.url, data: err.response.data },
        "backend request failed"
      );
    } else {
      logger.error(
        { err: { message: err.message }, url: err.config?.url },
        "backend request error"
      );
    }
    return Promise.reject(err);
  }
);

function withAuth(token) {
  if (!token) return client;
  return axios.create({
    baseURL: env.BACKEND_URL,
    timeout: env.BACKEND_REQUEST_TIMEOUT_MS,
    headers: { Accept: "application/json", Authorization: `Bearer ${token}` },
    validateStatus: (status) => status < 500,
  });
}

module.exports = {
  client,
  withAuth,
  async me(token) {
    const res = await withAuth(token).get("/auth/me");
    return res.data;
  },
  async searchDomain(token, domain) {
    const res = await withAuth(token).get(`/api/domains/search/${encodeURIComponent(domain)}`);
    return res.data;
  },
  async scanDomain(token, domain) {
    const res = await withAuth(token).post(`/api/domains/scan/${encodeURIComponent(domain)}`);
    return res.data;
  },
  async listReports(token, limit = 50) {
    const res = await withAuth(token).get(`/api/reports?limit=${limit}`);
    return res.data;
  },
  async dataleakSearch(token, query, source = "all") {
    const res = await withAuth(token).get(
      `/api/dataleak/search?q=${encodeURIComponent(query)}&source=${source}`
    );
    return res.data;
  },
};
