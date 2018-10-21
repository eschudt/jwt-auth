PROJECT?=jwt-auth
APP_VERSION?=0.0.1
GITHASH?=none-local
BUILDSTAMP?=none-local

build: Dockerfile *.go
	docker build -t eschudt/${PROJECT}:${APP_VERSION} \
		--build-arg 'APP_VERSION=${APP_VERSION}' \
		--build-arg 'GITHASH=${GITHASH}' \
		--build-arg 'PROJECT=${PROJECT}' \
		--build-arg 'BUILDSTAMP=${BUILDSTAMP}' \
		.

build-local: test
	go build -ldflags "-X 'main.buildstamp=${BUILDSTAMP}' -X 'main.githash=${GITHASH}' -X 'main.vpatch=${APP_VERSION}'" -o /app

run:
	docker run -it --rm -p 8080:8080 --name app eschudt/${PROJECT}:${APP_VERSION}

test: *.go
	/go/bin/dep ensure
	go fmt ./...
	go test -vet all ./...
