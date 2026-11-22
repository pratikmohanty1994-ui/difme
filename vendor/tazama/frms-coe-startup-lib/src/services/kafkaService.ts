// SPDX-License-Identifier: Apache-2.0
// DIFME patch (ADR-023): Kafka transport for the Tazama transaction plane, in place of NATS. DIFME already runs Kafka
// (Strimzi, KRaft); a second broker would be redundant. Same contract and payloads as NatsService:
//  - a NATS subject maps to a Kafka topic of the same name, with characters Kafka forbids (e.g. '@' in
//    `sub-rule-901@1.0.0`) replaced by '_' (topicFor);
//  - the NATS queue group (FUNCTION_NAME) becomes the consumer group, so instances of one processor share the work;
//  - messages stay protobuf-encoded FRMSMessage buffers;
//  - handlers stay fire-and-forget, as on NATS core (at-most-once), so throughput matches the NATS path;
//  - a processor's group starts at the earliest offset, so nothing published before it joined is lost (NATS core
//    would drop it; this is stricter);
//  - the service channel is broadcast: every instance consumes it with its own group, from the latest offset.
// Selected with STARTUP_TYPE=kafka; SERVER_URL holds the bootstrap servers (comma-separated host:port).

import { KafkaJS } from '@confluentinc/kafka-javascript';
import { hostname } from 'node:os';
import { randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import type { ILoggerService } from '../interfaces';
import { startupConfig } from '../interfaces/iStartupConfig';
import type { onMessageFunction } from '../types/onMessageFunction';
import type { IStartupService } from '..';
import { createMessageBuffer, decodeMessageBuffer } from '@tazama-lf/frms-coe-lib/lib/helpers/protobuf';
import { getLogger } from '../utils';

/** Kafka topic for a NATS-style subject: legal topic characters are [A-Za-z0-9._-]. */
export const topicFor = (subject: string): string => subject.replace(/[^A-Za-z0-9._-]/g, '_');

// New topics: partitions bound the parallelism of one processor's instances; replication 1 matches DIFME's dev Kafka.
const DEFAULT_PARTITIONS = 3;
// librdkafka refreshes topic metadata every 5 minutes by default; a topic created after a consumer subscribed would be
// invisible to it for that long. 10 s keeps new topics (e.g. a rule added to the network map) in reach quickly.
const METADATA_REFRESH = { 'topic.metadata.refresh.interval.ms': 10_000 };
const METADATA_WAIT_MS = 30_000;
const METADATA_POLL_MS = 250;
const DEFAULT_REPLICATION = 1;

const errorText = (err: unknown): string => (err instanceof Error ? err.message : JSON.stringify(err));

export class KafkaService implements IStartupService {
  kafka?: KafkaJS.Kafka;
  producer?: KafkaJS.Producer;
  consumer?: KafkaJS.Consumer;
  serviceConsumer?: KafkaJS.Consumer;
  producerStreamName = '';
  consumerStreamName: string[] | undefined;
  functionName = '';
  logger?: ILoggerService | Console;
  private onMessage?: onMessageFunction;
  private readonly topicChecks = new Map<string, Promise<void>>();
  private adminReady?: Promise<KafkaJS.Admin>;
  private producerReady?: Promise<KafkaJS.Producer>;

  private client(): KafkaJS.Kafka {
    this.kafka ??= new KafkaJS.Kafka({
      kafkaJS: {
        clientId: `${startupConfig.functionName}-${hostname()}`,
        brokers: startupConfig.serverUrl
          .split(',')
          .map((b) => b.trim())
          .filter(Boolean),
        logLevel: KafkaJS.logLevel.WARN,
      },
    });
    return this.kafka;
  }

  /**
   * Create the topics if they don't exist yet, so a consumer can subscribe before any producer ran. Concurrent callers
   * share one in-flight check per topic, and a topic another client created meanwhile counts as created.
   */
  private async ensureTopics(topics: string[]): Promise<void> {
    await Promise.all(
      topics.map(async (topic) => {
        let pending = this.topicChecks.get(topic);
        if (!pending) {
          pending = this.createTopic(topic);
          this.topicChecks.set(topic, pending);
          // A failed check is retried by the next caller rather than cached.
          pending.catch(() => this.topicChecks.delete(topic));
        }
        await pending;
      }),
    );
  }

  /**
   * Wait until the broker's metadata lists every topic with partitions. A consumer that subscribes to a topic another
   * client is still creating sees "Unknown topic or partition" and, with librdkafka's default 5-minute metadata
   * refresh, misses messages for minutes (found in the end-to-end test, 2026-11-22).
   */
  private async awaitTopicMetadata(topics: string[]): Promise<void> {
    const admin = await this.connectAdmin();
    const deadline = Date.now() + METADATA_WAIT_MS;
    for (;;) {
      try {
        const meta = await admin.fetchTopicMetadata({ topics });
        if (meta.length === topics.length && meta.every((t) => t.partitions.length > 0)) return;
      } catch {
        // not visible yet
      }
      if (Date.now() > deadline) throw new Error(`Kafka topics not visible after ${METADATA_WAIT_MS} ms: ${topics.join(', ')}`);
      await sleep(METADATA_POLL_MS);
    }
  }

  private async createTopic(topic: string): Promise<void> {
    const admin = await this.connectAdmin();
    if ((await admin.listTopics()).includes(topic)) return;
    try {
      await admin.createTopics({
        topics: [
          {
            topic,
            numPartitions: Number(process.env.KAFKA_TOPIC_PARTITIONS ?? DEFAULT_PARTITIONS),
            replicationFactor: Number(process.env.KAFKA_TOPIC_REPLICATION ?? DEFAULT_REPLICATION),
          },
        ],
      });
      this.logger?.log(`Created Kafka topic: ${topic}`);
    } catch (err) {
      if (!/already exists/i.test(errorText(err))) throw err;
    }
  }

  // This client allows connect() once per object; concurrent first callers share one connect.
  private async connectAdmin(): Promise<KafkaJS.Admin> {
    this.adminReady ??= (async () => {
      const admin = this.client().admin();
      await admin.connect();
      return admin;
    })();
    return await this.adminReady;
  }

  private async connectProducer(): Promise<KafkaJS.Producer> {
    this.producerReady ??= (async () => {
      const producer = this.client().producer({ kafkaJS: { allowAutoTopicCreation: false, acks: 1 } });
      await producer.connect();
      this.producer = producer;
      return producer;
    })();
    return await this.producerReady;
  }

  async init(
    onMessage: onMessageFunction,
    loggerService?: ILoggerService,
    parConsumerStreamNames?: string[],
    parProducerStreamName?: string,
  ): Promise<boolean> {
    if (!startupConfig.consumerStreamName && !parConsumerStreamNames?.length) {
      throw new Error('No Consumer Stream Name Provided in environmental Variable or on startup as an arguement');
    }
    if (parProducerStreamName) startupConfig.producerStreamName = parProducerStreamName;
    if (parConsumerStreamNames) startupConfig.consumerStreamName = String(parConsumerStreamNames);

    await this.initProducer(loggerService, parProducerStreamName);
    this.onMessage = onMessage;
    this.consumerStreamName = startupConfig.consumerStreamName.split(',').filter(Boolean);
    await this.startConsumer();
    return true;
  }

  private async startConsumer(): Promise<void> {
    const topics = (this.consumerStreamName ?? []).map(topicFor);
    await this.ensureTopics(topics);
    await this.awaitTopicMetadata(topics);
    this.consumer = this.client().consumer({
      // A new group starts at the earliest offset: messages published before its first partition assignment are
      // processed, not skipped. Afterwards the group resumes from its committed offset.
      kafkaJS: { groupId: this.functionName, fromBeginning: true, allowAutoTopicCreation: false },
      ...METADATA_REFRESH,
    });
    await this.consumer.connect();
    await this.consumer.subscribe({ topics });
    await this.consumer.run({
      // eslint-disable-next-line @typescript-eslint/require-await -- the handler is fire-and-forget, as on NATS core
      eachMessage: async ({ topic, message }) => {
        if (!message.value || !this.onMessage) return;
        this.logger?.log(`${Date.now().toLocaleString()} topic:[${topic}]: ${message.value.length}`);
        try {
          const handled = this.onMessage(decodeMessageBuffer(message.value), (msg) => {
            this.handleResponse(msg).catch((err: unknown) => {
              this.logger?.error(`Error handling response on default path: ${errorText(err)}`);
            });
          });
          void Promise.resolve(handled).catch((err: unknown) => {
            this.logger?.error(`Error in message handler on default path: ${errorText(err)}`);
          });
        } catch (err: unknown) {
          this.logger?.error(`Error in message handler on default path: ${errorText(err)}`);
        }
      },
    });
    this.logger?.log(`Consuming ${topics.join(', ')} as group ${this.functionName}`);
  }

  /** Add consumer subjects at runtime: Kafka can't extend a running subscription, so the consumer restarts with the union. */
  async addConsumers(subjects: string[], onMessage: onMessageFunction): Promise<boolean> {
    if (!this.producer) {
      this.logger?.warn('addConsumers called with no live Kafka connection; nothing subscribed');
      return false;
    }
    const existing = this.consumerStreamName ?? [];
    const toAdd = [...new Set(subjects.filter((s) => s && !existing.includes(s)))];
    if (!toAdd.length) return true;
    this.consumerStreamName = [...existing, ...toAdd];
    this.onMessage = onMessage;
    if (this.consumer) await this.consumer.disconnect();
    await this.startConsumer();
    return true;
  }

  async initProducer(loggerService?: ILoggerService, parProducerStreamName?: string): Promise<boolean> {
    this.validateEnvironment();
    this.logger = getLogger(startupConfig, loggerService);
    try {
      this.logger.log(`Attempting connection to Kafka, with config:\n${JSON.stringify(startupConfig)}`);
      await this.connectProducer();
      this.functionName = startupConfig.functionName.replace(/\./g, '_');
      this.producerStreamName = parProducerStreamName ?? startupConfig.producerStreamName;
      this.logger.log(`Connected to Kafka ${startupConfig.serverUrl}`);
    } catch (err) {
      this.logger.log(`Error communicating with Kafka on: ${startupConfig.serverUrl}, with error: ${errorText(err)}`);
      throw err instanceof Error ? err : new Error(errorText(err));
    }
    return true;
  }

  validateEnvironment(): void {
    if (!startupConfig.serverUrl) throw new Error('No Server URL was Provided in environmental Variable');
    if (!startupConfig.functionName) throw new Error('No Function Name was Provided in environmental Variable');
  }

  async handleResponse(response: object, subject?: string[]): Promise<void> {
    if (!this.producer) return;
    const value = createMessageBuffer(response as Record<string, unknown>);
    if (!value) throw new Error('Response could not be encoded as an FRMSMessage; nothing published.');
    const subjects = subject?.length ? subject : this.producerStreamName ? [this.producerStreamName] : [];
    if (!subjects.length) {
      throw new Error('No subject supplied and no PRODUCER_STREAM configured; cannot determine a publish destination.');
    }
    const topics = subjects.map(topicFor);
    await this.ensureTopics(topics);
    // Keyed by transaction id: spreads load over partitions (and so over a processor's instances) and keeps one
    // transaction's messages in order.
    const txId = (response as { transactionID?: unknown }).transactionID;
    const key = typeof txId === 'string' && txId ? txId : null;
    await this.producer.sendBatch({ topicMessages: topics.map((topic) => ({ topic, messages: [{ key, value }] })) });
  }

  // ---- Service channel: opaque bytes, broadcast to every instance (NATS: plain subscription, no queue group) ----

  async initServiceChannelProducer(loggerService?: ILoggerService): Promise<boolean> {
    this.logger = getLogger(startupConfig, loggerService);
    try {
      await this.connectProducer();
      this.functionName = startupConfig.functionName.replace(/\./g, '_');
      return true;
    } catch (err) {
      this.logger.log(`Service-channel connect failed (non-fatal): ${errorText(err)}`);
      return false;
    }
  }

  async publishServiceChannel(body: Uint8Array, subject?: string): Promise<void> {
    const target = subject ?? startupConfig.serviceChannelProducer;
    if (!target) throw new Error('No subject provided and SERVICE_CHANNEL_PRODUCER is not set in the environment.');
    if (!this.producer) {
      this.logger?.warn(`Service-channel publish skipped (no live connection): ${body.length} bytes dropped for subject:[${target}]`);
      return;
    }
    const topic = topicFor(target);
    await this.ensureTopics([topic]);
    await this.producer.send({ topic, messages: [{ value: Buffer.from(body) }] });
    this.logger?.log(`Service-channel published ${body.length} bytes to subject:[${target}]`);
  }

  async initServiceChannel(
    onMessage: (data: Uint8Array) => void | Promise<void>,
    subject?: string,
    loggerService?: ILoggerService,
  ): Promise<boolean> {
    const target = subject ?? startupConfig.serviceChannelConsumer;
    if (!target) throw new Error('No subject provided and SERVICE_CHANNEL_CONSUMER is not set in the environment.');
    if (loggerService) this.logger = getLogger(startupConfig, loggerService);
    if (!this.producer) return false;
    const topic = topicFor(target);
    await this.ensureTopics([topic]);
    // A group of its own per instance = broadcast fan-out, like a NATS subscription without a queue group.
    this.serviceConsumer = this.client().consumer({
      kafkaJS: { groupId: `${this.functionName}-svc-${randomUUID()}`, fromBeginning: false, allowAutoTopicCreation: false },
      ...METADATA_REFRESH,
    });
    await this.serviceConsumer.connect();
    await this.serviceConsumer.subscribe({ topics: [topic] });
    await this.serviceConsumer.run({
      eachMessage: async ({ message }) => {
        if (!message.value) return;
        try {
          await onMessage(new Uint8Array(message.value));
        } catch (err: unknown) {
          this.logger?.error(`Service-channel handler threw on subject:[${target}]: ${errorText(err)}`);
        }
      },
    });
    return true;
  }
}
