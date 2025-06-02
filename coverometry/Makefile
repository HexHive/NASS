DOCKER := docker

.PHONY: build run help

help: ## Show this help
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: Dockerfile compose.yaml ## Build the Docker container(s)
	@$(DOCKER) compose build

run:
	@$(DOCKER) compose run --rm coverometry /bin/bash
