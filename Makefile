.PHONY: docker

docker:
	docker build -t lthummus/auththingie2 .

mulitdocker:
	docker buildx build --platform=linux/amd64,linux/arm64,linux/arm/v7 .

