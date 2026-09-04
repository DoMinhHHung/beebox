module github.com/DoMinhHHung/beebox/beebox-projects

go 1.22

require (
	github.com/DoMinhHHung/beebox/beebox-apperror v0.0.0
	github.com/DoMinhHHung/beebox/beebox-id v0.0.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.7.4
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)

replace github.com/DoMinhHHung/beebox/beebox-apperror => ../beebox-apperror

replace github.com/DoMinhHHung/beebox/beebox-id => ../beebox-id
