import axios from 'axios';
import { SocksProxyAgent } from 'socks-proxy-agent';
import config from '../config';
import logger from '../logger';

/**
 * Spamchain replay detection.
 *
 * Bitcoin-BLAKE2b (XBT) and the legacy SHA-256 chain ("the Spamchain") share all
 * pre-fork history, so a transaction can exist on both. For a given XBT txid we ask
 * a SHA-256 explorer whether the same txid is confirmed/pending there, and whether
 * its outputs have already been spent on that chain — the point where the coins of
 * the two chains diverge. Lookups go through Tor (if SOCKS5PROXY is enabled) so the
 * third-party explorer does not learn which transactions are being inspected.
 */

export type SpamchainStatusCode =
  | 'replayed'        // same txid confirmed on the Spamchain, outputs still unspent there
  | 'replayed_spent'  // same txid confirmed on the Spamchain AND outputs already spent there
  | 'mempool'         // same txid sitting in the Spamchain mempool
  | 'only_xbt'        // not found on the Spamchain: only on Bitcoin-BLAKE2b
  | 'disabled'        // feature turned off
  | 'error';          // could not reach the Spamchain source

export interface SpamchainStatus {
  status: SpamchainStatusCode;
  shaBlockHeight?: number;
  spentOutputs?: number;
  totalOutputs?: number;
  checkedAt: number;
}

interface CacheEntry {
  value: SpamchainStatus;
  expiry: number;
}

class Spamchain {
  private cache: Map<string, CacheEntry> = new Map();
  private readonly CONFIRMED_TTL = 24 * 3600 * 1000; // confirmed / "only_xbt" answers are stable
  private readonly MEMPOOL_TTL = 60 * 1000;          // pending answers change fast
  private readonly ERROR_TTL = 15 * 1000;            // don't hammer a failing source
  private readonly MAX_CACHE = 20000;

  public async $check(txid: string): Promise<SpamchainStatus> {
    if (!config.SPAMCHAIN.ENABLED) {
      return { status: 'disabled', checkedAt: Date.now() };
    }
    const cached = this.cache.get(txid);
    if (cached && cached.expiry > Date.now()) {
      return cached.value;
    }

    let result: SpamchainStatus;
    try {
      result = await this.$lookup(txid);
    } catch (e) {
      logger.debug(`Spamchain lookup failed for ${txid}: ` + (e instanceof Error ? e.message : e));
      result = { status: 'error', checkedAt: Date.now() };
    }

    const ttl = result.status === 'mempool' ? this.MEMPOOL_TTL
      : result.status === 'error' ? this.ERROR_TTL
      : this.CONFIRMED_TTL;
    this.setCache(txid, { value: result, expiry: Date.now() + ttl });
    return result;
  }

  private async $lookup(txid: string): Promise<SpamchainStatus> {
    const base = config.SPAMCHAIN.API.replace(/\/+$/, '');

    const tx = await this.$fetch(`${base}/tx/${txid}`);
    if (tx.status === 404 || !tx.data || typeof tx.data !== 'object') {
      return { status: 'only_xbt', checkedAt: Date.now() };
    }

    const confirmed = tx.data.status?.confirmed === true;
    if (!confirmed) {
      return { status: 'mempool', checkedAt: Date.now() };
    }

    const shaBlockHeight: number | undefined = tx.data.status?.block_height;
    let spentOutputs = 0;
    let totalOutputs: number | undefined = Array.isArray(tx.data.vout) ? tx.data.vout.length : undefined;

    // Outputs still unspent on the Spamchain => just a replay; already spent => coins diverged.
    try {
      const outspends = await this.$fetch(`${base}/tx/${txid}/outspends`);
      if (outspends.status === 200 && Array.isArray(outspends.data)) {
        spentOutputs = outspends.data.filter((o) => o && o.spent).length;
        totalOutputs = outspends.data.length;
      }
    } catch (e) {
      logger.debug(`Spamchain outspends lookup failed for ${txid}: ` + (e instanceof Error ? e.message : e));
    }

    return {
      status: spentOutputs > 0 ? 'replayed_spent' : 'replayed',
      shaBlockHeight,
      spentOutputs,
      totalOutputs,
      checkedAt: Date.now(),
    };
  }

  private async $fetch(url: string): Promise<{ status: number; data: any }> {
    const options: any = {
      headers: { 'User-Agent': 'mempool' },
      timeout: config.SOCKS5PROXY.ENABLED ? 30000 : 15000,
      // Treat 404 as a normal answer ("not on the Spamchain"), not an error to retry on.
      validateStatus: (s: number) => s === 200 || s === 404,
    };
    if (config.SOCKS5PROXY.ENABLED) {
      const socksOptions: any = {
        agentOptions: { keepAlive: true },
        hostname: config.SOCKS5PROXY.HOST,
        port: config.SOCKS5PROXY.PORT,
      };
      if (config.SOCKS5PROXY.USERNAME && config.SOCKS5PROXY.PASSWORD) {
        socksOptions.username = config.SOCKS5PROXY.USERNAME;
        socksOptions.password = config.SOCKS5PROXY.PASSWORD;
      }
      options.httpsAgent = new SocksProxyAgent(socksOptions);
    }
    const r = await axios.get(url, options);
    return { status: r.status, data: r.data };
  }

  private setCache(txid: string, entry: CacheEntry): void {
    if (this.cache.size >= this.MAX_CACHE) {
      const drop = Math.ceil(this.MAX_CACHE * 0.1);
      let i = 0;
      for (const k of this.cache.keys()) {
        this.cache.delete(k);
        if (++i >= drop) {
          break;
        }
      }
    }
    this.cache.set(txid, entry);
  }
}

export default new Spamchain();
