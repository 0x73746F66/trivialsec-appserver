SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
PACKAGE_NAME = appserver

.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

setup-stripe-linux:
	wget -qO - https://github.com/stripe/stripe-cli/releases/download/v1.6.1/stripe_1.6.1_linux_x86_64.tar.gz | tar xvz && ./stripe
	./stripe login

prep:
	@find . -type f -name '*.pyc' -delete 2>/dev/null
	@find . -type d -name '__pycache__' -delete 2>/dev/null
	@find . -type f -name '*.DS_Store' -delete 2>/dev/null
	@rm -f **/*.zip **/*.tar **/*.tgz **/*.gz
	@rm -rf build

python-libs: prep
	yes | pip uninstall -q trivialsec-common
ifdef AWS_PROFILE
	aws --profile $(AWS_PROFILE) s3 cp --only-show-errors s3://static-trivialsec/deploy-packages/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl
	aws --profile $(AWS_PROFILE) s3 cp --only-show-errors s3://static-trivialsec/deploy-packages/${COMMON_VERSION}/build.tgz build.tgz
else
	aws s3 cp --only-show-errors s3://static-trivialsec/deploy-packages/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl
	aws s3 cp --only-show-errors s3://static-trivialsec/deploy-packages/${COMMON_VERSION}/build.tgz build.tgz
endif
	tar -xzvf build.tgz
	pip install -q --no-cache-dir --find-links=build/wheel --no-index trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl
	@rm -rf build || true
	@rm build.tgz trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl || true

install-dev: python-libs
	pip install -q -U pip setuptools wheel
	pip install -q -U --no-cache-dir --isolated -r ./docker/requirements.txt

test-local:
	pylint --exit-zero -f colorized --persistent=y -r y --jobs=0 src/**/*.py
	semgrep -q --strict --timeout=0 --config=p/ci --lang=py src/**/*.py
	semgrep -q --strict --config p/minusworld.flask-xss --lang=py src/**/*.py

lint:
	pylint --exit-zero --persistent=n -f json -r n --jobs=0 --errors-only src/**/*.py > pylint.json

sast:
	semgrep --disable-version-check -q --strict --error -o semgrep-ci.json --json --timeout=0 --config=p/ci --lang=py src/**/*.py

xss:
	semgrep --disable-version-check -q --strict --error -o semgrep-flask-xss.json --json --config p/minusworld.flask-xss --lang=py src/**/*.py

test-all: xss sast lint

stripe-dev:
	./stripe listen --forward-to localhost:5000/webhook/stripe

build: ## Build compressed container
	docker-compose build --compress

buildnc: python-libs ## Clean build docker
	docker-compose build --no-cache --compress

rebuild: down build

push:
	docker-compose push

docker-login:
	@echo $(shell [ -z "${DOCKER_PASSWORD}" ] && echo "DOCKER_PASSWORD missing" )
	@echo ${DOCKER_PASSWORD} | docker login -u ${DOCKER_USER} --password-stdin registry.gitlab.com

docker-clean: ## Fixes some issues with docker
	docker rmi $(docker images -qaf "dangling=true")
	yes | docker system prune
	sudo service docker restart

docker-purge: ## tries to compeltely remove all docker files and start clean
	docker rmi $(docker images -qa)
	yes | docker system prune
	sudo service docker stop
	sudo rm -rf /tmp/docker.backup/
	sudo cp -Pfr /var/lib/docker /tmp/docker.backup
	sudo rm -rf /var/lib/docker
	sudo service docker start

up: prep ## Start the app
	docker-compose up -d

down: ## Stop the app
	@docker-compose down --remove-orphans

restart: down up
