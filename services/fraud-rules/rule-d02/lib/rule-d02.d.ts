import type { DatabaseManagerInstance, LoggerService, ManagerConfig } from '@tazama-lf/frms-coe-lib';
import type { RuleConfig, RuleRequest, RuleResult } from '@tazama-lf/frms-coe-lib/lib/interfaces';
export declare const RULE_ID = "D02";
export type RuleExecutorConfig = ManagerConfig & Required<Pick<ManagerConfig, 'eventHistory'>>;
export declare function handleTransaction(req: RuleRequest, determineOutcome: (value: number, ruleConfig: RuleConfig, ruleResult: RuleResult) => RuleResult, ruleRes: RuleResult, loggerService: LoggerService, ruleConfig: RuleConfig, databaseManager: DatabaseManagerInstance<RuleExecutorConfig>): Promise<RuleResult>;
