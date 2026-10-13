import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_API_BASE_URL,
  checkApiHealth,
  predictSingleQuery,
  analyzeBatchQueries,
} from './client.js';

describe('API Client Tests', () => {
  it('DEFAULT_API_BASE_URL is empty string for Vite dev proxy routing', () => {
    assert.equal(DEFAULT_API_BASE_URL, '');
  });

  describe('checkApiHealth', () => {
    it('successfully calls /health and returns parsed JSON', async () => {
      const originalFetch = globalThis.fetch;
      try {
        globalThis.fetch = async (url, options) => {
          assert.equal(url, 'http://127.0.0.1:8000/health');
          assert.equal(options.method, 'GET');
          return {
            ok: true,
            status: 200,
            json: async () => ({ status: 'healthy', model_loaded: true }),
          };
        };

        const result = await checkApiHealth('http://127.0.0.1:8000');
        assert.deepEqual(result, { status: 'healthy', model_loaded: true });
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('formats network error cleanly when backend is offline', async () => {
      const originalFetch = globalThis.fetch;
      try {
        globalThis.fetch = async () => {
          throw new TypeError('Failed to fetch');
        };

        await assert.rejects(
          async () => await checkApiHealth('http://127.0.0.1:8000'),
          /Failed to connect to API endpoint/
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  describe('predictSingleQuery', () => {
    it('constructs correct payload and returns prediction data', async () => {
      const originalFetch = globalThis.fetch;
      try {
        let sentBody;
        globalThis.fetch = async (url, options) => {
          assert.equal(url, '/predict');
          assert.equal(options.method, 'POST');
          assert.equal(options.headers['Content-Type'], 'application/json');
          sentBody = JSON.parse(options.body);

          return {
            ok: true,
            status: 200,
            json: async () => ({
              prediction: 'suspicious',
              label: 1,
              attack_probability: 0.992,
              decision_threshold: 0.89,
            }),
          };
        };

        const queryInput = {
          timestamp: '  2026-10-12T00:00:00Z  ',
          src_ip: '10.0.0.1',
          dst_ip: '8.8.8.8',
          requested_server_name: 'test.tunnel.com',
          query_type: 'TXT',
        };

        const result = await predictSingleQuery(queryInput, '');
        assert.equal(sentBody.timestamp, '2026-10-12T00:00:00Z');
        assert.equal(sentBody.requested_server_name, 'test.tunnel.com');
        assert.equal(sentBody.query_type, 'TXT');
        assert.equal(sentBody.source, 'CyberTrace Dashboard');
        assert.equal(result.prediction, 'suspicious');
        assert.equal(result.label, 1);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it('handles backend 422 validation errors and extracts detail message', async () => {
      const originalFetch = globalThis.fetch;
      try {
        globalThis.fetch = async () => {
          return {
            ok: false,
            status: 422,
            statusText: 'Unprocessable Entity',
            json: async () => ({
              detail: 'Field required: requested_server_name',
            }),
          };
        };

        await assert.rejects(
          async () => await predictSingleQuery({}),
          /Field required: requested_server_name/
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  describe('analyzeBatchQueries', () => {
    it('constructs batch payload with array of queries and returns aggregate results', async () => {
      const originalFetch = globalThis.fetch;
      try {
        let sentBody;
        globalThis.fetch = async (url, options) => {
          assert.equal(url, 'http://localhost:8000/analyze');
          sentBody = JSON.parse(options.body);
          return {
            ok: true,
            status: 200,
            json: async () => ({
              total_queries: 2,
              suspicious_queries: 1,
              benign_queries: 1,
              results: [
                {
                  requested_server_name: 'google.com',
                  prediction: 'benign',
                  label: 0,
                  attack_probability: 0.0001,
                  decision_threshold: 0.89,
                },
                {
                  requested_server_name: 'bad.tunnel.net',
                  prediction: 'suspicious',
                  label: 1,
                  attack_probability: 0.95,
                  decision_threshold: 0.89,
                },
              ],
            }),
          };
        };

        const batch = [
          {
            timestamp: '2026-10-12T00:00:01Z',
            src_ip: '192.168.1.1',
            dst_ip: '8.8.8.8',
            requested_server_name: 'google.com',
            query_type: 'A',
          },
          {
            timestamp: '2026-10-12T00:00:02Z',
            src_ip: '10.0.0.1',
            dst_ip: '8.8.8.8',
            requested_server_name: 'bad.tunnel.net',
            query_type: 'TXT',
          },
        ];

        const response = await analyzeBatchQueries(batch, 'http://localhost:8000');
        assert.equal(sentBody.queries.length, 2);
        assert.equal(response.total_queries, 2);
        assert.equal(response.suspicious_queries, 1);
        assert.equal(response.results.length, 2);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });
});
