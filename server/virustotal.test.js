const { isPrivateIP, checkPublicIP } = require('./virustotal.js');

// Mock fetch API
global.fetch = jest.fn();

describe('VirusTotal Integration', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Clear module cache to reset vtCache between tests
    jest.resetModules();
  });

  // ======================================================================
  // isPrivateIP() Tests
  // ======================================================================
  describe('isPrivateIP()', () => {
    describe('Private IP Ranges', () => {
      test('should recognize 10.x.x.x as private', () => {
        expect(isPrivateIP('10.0.0.1')).toBe(true);
        expect(isPrivateIP('10.255.255.254')).toBe(true);
        expect(isPrivateIP('10.1.2.3')).toBe(true);
      });

      test('should recognize 172.16-31.x.x as private', () => {
        expect(isPrivateIP('172.16.0.1')).toBe(true);
        expect(isPrivateIP('172.20.5.10')).toBe(true);
        expect(isPrivateIP('172.31.255.254')).toBe(true);
      });

      test('should recognize 172.15.x.x as public (outside private range)', () => {
        expect(isPrivateIP('172.15.0.1')).toBe(false);
      });

      test('should recognize 172.32.x.x as public (outside private range)', () => {
        expect(isPrivateIP('172.32.0.1')).toBe(false);
      });

      test('should recognize 192.168.x.x as private', () => {
        expect(isPrivateIP('192.168.0.1')).toBe(true);
        expect(isPrivateIP('192.168.1.1')).toBe(true);
        expect(isPrivateIP('192.168.255.254')).toBe(true);
      });

      test('should recognize 127.x.x.x (localhost) as private', () => {
        expect(isPrivateIP('127.0.0.1')).toBe(true);
        expect(isPrivateIP('127.0.0.255')).toBe(true);
        expect(isPrivateIP('127.255.255.254')).toBe(true);
      });

      test('should recognize 169.254.x.x (link-local) as private', () => {
        expect(isPrivateIP('169.254.0.1')).toBe(true);
        expect(isPrivateIP('169.254.169.254')).toBe(true);
        expect(isPrivateIP('169.254.255.254')).toBe(true);
      });

      test('should recognize 169.253.x.x as public (outside link-local range)', () => {
        expect(isPrivateIP('169.253.0.1')).toBe(false);
      });

      test('should recognize 169.255.x.x as public (outside link-local range)', () => {
        expect(isPrivateIP('169.255.0.1')).toBe(false);
      });
    });

    describe('Public IP Addresses', () => {
      test('should recognize common public IPs as public', () => {
        expect(isPrivateIP('8.8.8.8')).toBe(false);        // Google DNS
        expect(isPrivateIP('1.1.1.1')).toBe(false);        // Cloudflare DNS
        expect(isPrivateIP('208.67.222.222')).toBe(false); // OpenDNS
      });

      test('should recognize various public IP ranges as public', () => {
        expect(isPrivateIP('11.0.0.1')).toBe(false);
        expect(isPrivateIP('50.100.150.200')).toBe(false);
        expect(isPrivateIP('200.50.100.150')).toBe(false);
      });
    });

    describe('Invalid IP Formats', () => {
      test('should return true for invalid IP formats', () => {
        expect(isPrivateIP('not-an-ip')).toBe(true);
        expect(isPrivateIP('256.0.0.1')).toBe(true);
        expect(isPrivateIP('192.168.1')).toBe(true);
        expect(isPrivateIP('192.168.1.1.1')).toBe(true);
        expect(isPrivateIP('192.168.a.1')).toBe(true);
        expect(isPrivateIP('')).toBe(true);
      });
    });
  });

  // ======================================================================
  // checkPublicIP() Tests
  // ======================================================================
  describe('checkPublicIP()', () => {
    beforeEach(() => {
      process.env.VIRUSTOTAL_API_KEY = 'test-api-key-123';
      jest.clearAllMocks();
    });

    afterEach(() => {
      delete process.env.VIRUSTOTAL_API_KEY;
    });

    describe('Private IP Handling', () => {
      test('should skip private IPs without calling API', async () => {
        const result = await checkPublicIP('192.168.1.1');

        expect(result).toEqual({
          skipped: true,
          message: "Private IP address — not sent to VirusTotal (local network only)",
          ip: '192.168.1.1',
          vtSeverity: "low"
        });
        expect(global.fetch).not.toHaveBeenCalled();
      });

      test('should skip localhost without calling API', async () => {
        const result = await checkPublicIP('127.0.0.1');
        expect(result.skipped).toBe(true);
        expect(global.fetch).not.toHaveBeenCalled();
      });

      test('should skip 10.x.x.x without calling API', async () => {
        const result = await checkPublicIP('10.0.0.1');
        expect(result.skipped).toBe(true);
        expect(global.fetch).not.toHaveBeenCalled();
      });

      test('should skip 172.16-31.x.x without calling API', async () => {
        const result = await checkPublicIP('172.20.5.5');
        expect(result.skipped).toBe(true);
        expect(global.fetch).not.toHaveBeenCalled();
      });

      test('should skip link-local IPs without calling API', async () => {
        const result = await checkPublicIP('169.254.169.254');
        expect(result.skipped).toBe(true);
        expect(global.fetch).not.toHaveBeenCalled();
      });
    });

    describe('API Key Configuration', () => {
      test('should return error when API key is not configured', async () => {
        delete process.env.VIRUSTOTAL_API_KEY;
        
        const result = await checkPublicIP('8.8.8.8');
        expect(result).toEqual({ error: 'VT API key not configured' });
        expect(global.fetch).not.toHaveBeenCalled();
      });
    });

    describe('Successful API Calls', () => {
      test('should fetch and return data for public IP', async () => {
        const mockData = {
          data: {
            attributes: {
              last_analysis_stats: { malicious: 1, suspicious: 0, undetected: 50 }
            }
          }
        };

        global.fetch.mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: jest.fn().resolvedValue(mockData)
        });

        const result = await checkPublicIP('8.8.8.8');

        expect(result).toEqual(mockData);
        expect(global.fetch).toHaveBeenCalledWith(
          'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8',
          { headers: { 'x-apikey': 'test-api-key-123' } }
        );
      });

      test('should properly encode IP in URL', async () => {
        global.fetch.mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: jest.fn().resolvedValue({ status: 'ok' })
        });

        await checkPublicIP('8.8.8.8');

        const callUrl = global.fetch.mock.calls[0][0];
        expect(callUrl).toContain('8.8.8.8');
      });
    });

    describe('Rate Limiting', () => {
      test('should return rate limit error on 429 status', async () => {
        global.fetch.mockResolvedValueOnce({
          status: 429,
          ok: false
        });

        const result = await checkPublicIP('8.8.8.8');

        expect(result).toEqual({ error: 'Rate limit exceeded' });
      });
    });

    describe('API Errors', () => {
      test('should handle 404 Not Found', async () => {
        global.fetch.mockResolvedValueOnce({
          status: 404,
          ok: false
        });

        const result = await checkPublicIP('8.8.8.8');

        expect(result).toHaveProperty('error');
        expect(result.error).toContain('VT API 404');
      });

      test('should handle 401 Unauthorized', async () => {
        global.fetch.mockResolvedValueOnce({
          status: 401,
          ok: false
        });

        const result = await checkPublicIP('8.8.8.8');

        expect(result).toHaveProperty('error');
        expect(result.error).toContain('VT API 401');
      });

      test('should handle 500 Server Error', async () => {
        global.fetch.mockResolvedValueOnce({
          status: 500,
          ok: false
        });

        const result = await checkPublicIP('8.8.8.8');

        expect(result).toHaveProperty('error');
        expect(result.error).toContain('VT API 500');
      });

      test('should handle network fetch errors', async () => {
        global.fetch.mockRejectedValueOnce(new Error('Network timeout'));

        const result = await checkPublicIP('8.8.8.8');

        expect(result).toEqual({ error: 'Network timeout' });
      });

      test('should handle JSON parse errors', async () => {
        global.fetch.mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: jest.fn().rejectedValue(new Error('Invalid JSON'))
        });

        const result = await checkPublicIP('8.8.8.8');

        expect(result).toEqual({ error: 'Invalid JSON' });
      });
    });

    describe('Cache Behavior', () => {
      test('should make API call on first request', async () => {
        global.fetch.mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: jest.fn().resolvedValue({ cached: false })
        });

        await checkPublicIP('1.1.1.1');

        expect(global.fetch).toHaveBeenCalledTimes(1);
      });

      test('should cache successful responses', async () => {
        const mockData = { data: { test: true } };

        global.fetch.mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: jest.fn().resolvedValue(mockData)
        });

        const result1 = await checkPublicIP('1.1.1.1');
        expect(result1).toEqual(mockData);
        expect(global.fetch).toHaveBeenCalledTimes(1);

        // Second call should use cache (no new fetch)
        const result2 = await checkPublicIP('1.1.1.1');
        expect(result2).toEqual(mockData);
        expect(global.fetch).toHaveBeenCalledTimes(1); // Still 1, not 2
      });

      test('should return cached data within TTL window', async () => {
        const mockData = { cached: true };

        global.fetch.mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: jest.fn().resolvedValue(mockData)
        });

        await checkPublicIP('1.1.1.1');
        
        // Immediately call again - should use cache
        const result = await checkPublicIP('1.1.1.1');
        
        expect(result).toEqual(mockData);
        expect(global.fetch).toHaveBeenCalledTimes(1);
      });

      test('should use separate cache entries for different IPs', async () => {
        const mockData1 = { ip: '1.1.1.1' };
        const mockData2 = { ip: '8.8.8.8' };

        global.fetch
          .mockResolvedValueOnce({
            status: 200,
            ok: true,
            json: jest.fn().resolvedValue(mockData1)
          })
          .mockResolvedValueOnce({
            status: 200,
            ok: true,
            json: jest.fn().resolvedValue(mockData2)
          });

        const result1 = await checkPublicIP('1.1.1.1');
        const result2 = await checkPublicIP('8.8.8.8');

        expect(result1).toEqual(mockData1);
        expect(result2).toEqual(mockData2);
        expect(global.fetch).toHaveBeenCalledTimes(2);
      });
    });

    describe('Edge Cases', () => {
      test('should handle empty string gracefully', async () => {
        const result = await checkPublicIP('');
        expect(result.skipped).toBe(true);
      });

      test('should handle very large IP numbers gracefully', async () => {
        const result = await checkPublicIP('999.999.999.999');
        expect(result.skipped).toBe(true);
      });

      test('should handle IPs with leading zeros', async () => {
        const result = await checkPublicIP('008.008.008.008');
        expect(result.skipped).toBe(false); // Should try to check (8.8.8.8)
      });
    });

    describe('Integration Tests', () => {
      test('complete workflow: private IP check then public IP check', async () => {
        // Private IP - should skip
        const privateResult = await checkPublicIP('192.168.1.1');
        expect(privateResult.skipped).toBe(true);

        // Public IP - should call API
        global.fetch.mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: jest.fn().resolvedValue({ data: { test: true } })
        });

        const publicResult = await checkPublicIP('8.8.8.8');
        expect(publicResult).toHaveProperty('data');
        expect(global.fetch).toHaveBeenCalledTimes(1);
      });

      test('should handle multiple consecutive API calls', async () => {
        global.fetch
          .mockResolvedValueOnce({
            status: 200,
            ok: true,
            json: jest.fn().resolvedValue({ ip: '1.1.1.1' })
          })
          .mockResolvedValueOnce({
            status: 200,
            ok: true,
            json: jest.fn().resolvedValue({ ip: '8.8.8.8' })
          })
          .mockResolvedValueOnce({
            status: 200,
            ok: true,
            json: jest.fn().resolvedValue({ ip: '208.67.222.222' })
          });

        const result1 = await checkPublicIP('1.1.1.1');
        const result2 = await checkPublicIP('8.8.8.8');
        const result3 = await checkPublicIP('208.67.222.222');

        expect(result1).toEqual({ ip: '1.1.1.1' });
        expect(result2).toEqual({ ip: '8.8.8.8' });
        expect(result3).toEqual({ ip: '208.67.222.222' });
        expect(global.fetch).toHaveBeenCalledTimes(3);
      });
    });
  });
});
