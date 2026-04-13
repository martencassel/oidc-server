tidy:
	go mod tidy

build: tidy
	go build -o ./bin/

run: tidy
	go run .


gen-keys:
	openssl genrsa -out oidc.key 2048
	openssl rsa -in oidc.key -pubout -out oidc.pub
