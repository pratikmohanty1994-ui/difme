-- DIFME test configuration (ADR-023): one typology from public rules 901 + 902 (alert at 200, interdiction at 400) and
-- a network map routing pacs.002.001.12 to it. Loaded after vendor/tazama/stack-postgres/config/00-public-base.sql.
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
insert into network_map (configuration) values ('{
  "active": true, "name": "DIFME test network map", "cfg": "1.0.0", "tenantId": "DEFAULT",
  "messages": [{"id": "004@4.0.0", "cfg": "4.0.0", "txTp": "pacs.002.001.12",
    "typologies": [{"id": "typology-processor", "cfg": "difme-901-902@1.0.0",
      "rules": [{"id": "901@4.0.0", "cfg": "4.0.0"}, {"id": "902@4.0.0", "cfg": "4.0.0"}]}]}]
}');
