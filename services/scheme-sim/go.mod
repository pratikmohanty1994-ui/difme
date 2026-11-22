module github.com/pratikmohanty1294/difme/services/scheme-sim

go 1.26.0

require (
	github.com/jackc/pgx/v5 v5.13.0
	github.com/moov-io/iso8583 v0.26.4
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	github.com/yerden/go-util v1.1.4 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Built from the vendored copy (owner decision 2026-11-21: outside projects are copied into vendor/).
replace github.com/moov-io/iso8583 => ../../vendor/moov-iso8583
