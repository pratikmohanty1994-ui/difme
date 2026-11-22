#!/bin/sh
# Applies Tazama's schema and configuration (vendor/tazama/stack-postgres, v4.0.0) to databases prefixed tazama_
# (ADR-023: upstream's names, e.g. "configuration", are too generic for DIFME's shared Postgres). Used by the schema job
# in the fraud namespace and by ci/tazama-e2e.sh, so both run the same steps. Idempotent: the tables are created once,
# the rule/typology/network-map configuration is loaded only into an empty configuration store.
#   schema.sh <dir holding 00-CREATE.sql, 01-tcs-init.sql, 02-trs-init.sql, 00-public-base.sql, difme-network-map.sql>
# Connection from the standard PG* variables (PGHOST, PGUSER, PGPASSWORD); the databases must exist.
set -eu
dir=$1
q() { psql -v ON_ERROR_STOP=1 -q "$@"; }
# Upstream's "create database X;" lines are dropped (the databases are created with owner and prefix beforehand) and
# "\connect X;" becomes "\connect tazama_X;".
rewrite() { sed -E 's/^create database [a-z_]+;$//I; s/^\\connect ([a-z_]+);/\\connect tazama_\1;/' "$1"; }
until pg_isready -q -d tazama_configuration; do sleep 3; done
if [ "$(q -d tazama_configuration -tAc "select to_regclass('public.network_map') is not null")" != t ]; then
  for f in 00-CREATE.sql 01-tcs-init.sql 02-trs-init.sql; do rewrite "$dir/$f" | q -d postgres; done
  echo "tazama schema applied"
fi
if [ "$(q -d tazama_configuration -tAc 'select count(*) from rule')" = 0 ]; then
  for f in 00-public-base.sql difme-network-map.sql; do rewrite "$dir/$f" | q -d postgres; done
  echo "tazama configuration loaded"
fi
