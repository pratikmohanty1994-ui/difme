import type { DatabaseManagerInstance, LoggerService, ManagerConfig } from '@tazama-lf/frms-coe-lib';
import type { RuleConfig, RuleRequest, RuleResult } from '@tazama-lf/frms-coe-lib/lib/interfaces';
export declare const RULE_ID = "D01";
export type RuleExecutorConfig = ManagerConfig;
export declare function handleTransaction(req: RuleRequest, determineOutcome: (value: number, ruleConfig: RuleConfig, ruleResult: RuleResult) => RuleResult, ruleRes: RuleResult, loggerService: LoggerService, ruleConfig: RuleConfig, _databaseManager?: DatabaseManagerInstance<RuleExecutorConfig>): Promise<RuleResult>;
