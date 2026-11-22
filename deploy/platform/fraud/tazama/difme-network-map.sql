-- DIFME configuration (ADR-023): a typology from public rules 901 + 902 and one from DIFME's fraud-model rule D01, and a
-- network map routing pacs.002.001.12 to both. Loaded after vendor/tazama/stack-postgres/config/00-public-base.sql.
\connect configuration;
insert into typology (configuration) values ('{
  "typology_name": "DIFME-test-901-902", "id": "typology-processor", "cfg": "difme-901-902@1.0.0", "tenantId": "DEFAULT",
  "workflow": {"alertThreshold": 200, "interdictionThreshold": 400},
  "rules": [
    {"id": "901@4.0.0", "cfg": "4.0.0", "termId": "v901at400at400", "wghts": [{"ref": ".err", "wght": "0"}, {"ref": ".x00", "wght": "100"}, {"ref": ".01", "wght": "100"}, {"ref": ".02", "wght": "200"}, {"ref": ".03", "wght": "400"}]},
    {"id": "902@4.0.0", "cfg": "4.0.0", "termId": "v902at400at400", "wghts": [{"ref": ".err", "wght": "0"}, {"ref": ".x00", "wght": "100"}, {"ref": ".01", "wght": "100"}, {"ref": ".02", "wght": "200"}, {"ref": ".03", "wght": "400"}]}
  ],
  "expression": ["Add", "v901at400at400", "v902at400at400"]
}');


-- DIFME rule D01 (services/fraud-rules/rule-d01): the ONNX fraud model's probability x1000, banded like the scorer's own
-- decision (ALLOW < 0.15, REVIEW < 0.5, BLOCK).
insert into rule (configuration) values ('{
  "id": "D01@1.0.0", "cfg": "1.0.0", "tenantId": "DEFAULT", "desc": "ONNX fraud model (DIFME fraud scorer)",
  "config": {
    "parameters": {"timeoutMs": 300, "unknownDeviceId": "unknown"},
    "exitConditions": [{"subRuleRef": ".x00", "reason": "Incoming transaction is unsuccessful"}],
    "bands": [
      {"subRuleRef": ".01", "upperLimit": 150, "reason": "Model: low fraud probability (ALLOW)"},
      {"subRuleRef": ".02", "lowerLimit": 150, "upperLimit": 500, "reason": "Model: elevated fraud probability (REVIEW)"},
      {"subRuleRef": ".03", "lowerLimit": 500, "reason": "Model: high fraud probability (BLOCK)"}
    ]
  }
}');
-- DIFME rule D02 (services/fraud-rules/rule-d02): PDF §7.4 L1, amount z-score against the debtor's earlier payments
-- (90 days, at least 5): x100, banded at 2 and 3 standard deviations; too little history gives .x01 (no weight).
insert into rule (configuration) values ('{
  "id": "D02@1.0.0", "cfg": "1.0.0", "tenantId": "DEFAULT", "desc": "Amount anomaly vs the debtor history (PDF 7.4 L1)",
  "config": {
    "parameters": {"minHistory": 5, "maxQueryRange": 7776000000},
    "exitConditions": [{"subRuleRef": ".x00", "reason": "Incoming transaction is unsuccessful"},
                       {"subRuleRef": ".x01", "reason": "Insufficient payment history for an amount comparison"}],
    "bands": [
      {"subRuleRef": ".01", "upperLimit": 200, "reason": "Amount usual for the debtor"},
      {"subRuleRef": ".02", "lowerLimit": 200, "upperLimit": 300, "reason": "Amount 2-3 standard deviations above usual"},
      {"subRuleRef": ".03", "lowerLimit": 300, "reason": "Amount over 3 standard deviations above usual (z > 3)"}
    ]
  }
}');

-- REVIEW alerts (200), BLOCK interdicts (400); no score (.err) carries no weight.
insert into typology (configuration) values ('{
  "typology_name": "DIFME-fraud-model", "id": "typology-processor", "cfg": "difme-fraud-model@1.0.0", "tenantId": "DEFAULT",
  "workflow": {"alertThreshold": 200, "interdictionThreshold": 400},
  "rules": [
    {"id": "D01@1.0.0", "cfg": "1.0.0", "termId": "vD01at100at100", "wghts": [{"ref": ".err", "wght": "0"}, {"ref": ".x00", "wght": "0"}, {"ref": ".01", "wght": "0"}, {"ref": ".02", "wght": "200"}, {"ref": ".03", "wght": "400"}]},
    {"id": "D02@1.0.0", "cfg": "1.0.0", "termId": "vD02at100at100", "wghts": [{"ref": ".err", "wght": "0"}, {"ref": ".x00", "wght": "0"}, {"ref": ".x01", "wght": "0"}, {"ref": ".01", "wght": "0"}, {"ref": ".02", "wght": "100"}, {"ref": ".03", "wght": "200"}]}
  ],
  "expression": ["Add", "vD01at100at100", "vD02at100at100"]
}');

insert into network_map (configuration) values ('{
  "active": true, "name": "DIFME test network map", "cfg": "1.0.0", "tenantId": "DEFAULT",
  "messages": [{"id": "004@4.0.0", "cfg": "4.0.0", "txTp": "pacs.002.001.12",
    "typologies": [{"id": "typology-processor", "cfg": "difme-901-902@1.0.0",
      "rules": [{"id": "901@4.0.0", "cfg": "4.0.0"}, {"id": "902@4.0.0", "cfg": "4.0.0"}]},
     {"id": "typology-processor", "cfg": "difme-fraud-model@1.0.0",
      "rules": [{"id": "D01@1.0.0", "cfg": "1.0.0"}, {"id": "D02@1.0.0", "cfg": "1.0.0"}]}]}]
}');
