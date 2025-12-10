include .env

help:
	@echo ''
	@echo 'Usage: make [TARGET] [EXTRA_ARGUMENTS]'
	@echo 'Targets:'
	@echo 'make dev: make dev for development work'
	@echo 'make build: make build container'
	@echo 'clean: clean for all clear docker images'

dev:
	docker-compose down
	docker-compose up

build:
	docker-compose down
	docker-compose build

clean:
	docker-compose down -v

psql:
	psql paycrest

gen-ent:
	go run -mod=mod entgo.io/ent/cmd/ent generate ./ent/schema/

run: gen-ent
	air

seed:
	go run scripts/seed-db/main.go

test:
	go test -v ./...

test-coverage:
	go test $(go list ./... | grep -v /ent | grep -v /config | grep -v /database | grep -v /routers)  -coverprofile=coverage.out ./...
