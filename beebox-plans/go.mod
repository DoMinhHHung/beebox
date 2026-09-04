module github.com/DoMinhHHung/beebox/beebox-plans

go 1.25.0

require (
	github.com/DoMinhHHung/beebox/beebox-apperror v0.0.0
	github.com/DoMinhHHung/beebox/libs/shared v0.0.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.9.2
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.29.0 // indirect
)

replace github.com/DoMinhHHung/beebox/beebox-apperror => ../beebox-apperror

replace github.com/DoMinhHHung/beebox/libs/shared => ../libs/shared
