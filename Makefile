.PHONY: docker

fuzz:
	go test -fuzz FuzzInternalMatch -fuzzminimizetime 1x -fuzztime 15s ./internal/rules
	go test -fuzz FuzzUser_SetPassword -fuzzminimizetime 1x -fuzztime 15s ./internal/user

docker:
	docker build -t lthummus/auththingie2 .

mulitdocker:
	docker buildx build --platform=linux/amd64,linux/arm64,linux/arm/v7 .

