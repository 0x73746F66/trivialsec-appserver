SHELL := /bin/bash
include .env
export $(shell sed 's/=.*//' .env)
APP_NAME = app

.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

CMD_AWS := aws
ifdef AWS_PROFILE
CMD_AWS += --profile $(AWS_PROFILE)
endif
ifdef AWS_REGION
CMD_AWS += --region $(AWS_REGION)
endif

prep:
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	find . -type d -name '__pycache__' -delete 2>/dev/null || true
	find . -type f -name '*.DS_Store' -delete 2>/dev/null || true
	@rm *.zip *.whl || true
	@rm -rf build || true

common: prep
	yes | pip uninstall -q trivialsec-common
	aws s3 cp --only-show-errors s3://cloudformation-trivialsec/deploy-packages/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl
	aws s3 cp --only-show-errors s3://cloudformation-trivialsec/deploy-packages/build-${COMMON_VERSION}.zip build.zip
	unzip -q build.zip
	pip install -q --no-cache-dir --find-links=build/wheel --no-index trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl

lint:
	pylint --jobs=0 --persistent=y --errors-only src/**/*.py

build: prep package-dev
	docker-compose build --compress

buildnc: prep package-dev
	docker-compose build --no-cache --compress

rebuild: down build run

docker-clean:
	docker rmi $(docker images -qaf "dangling=true")
	yes | docker system prune
	sudo service docker restart

docker-purge:
	docker rmi $(docker images -qa)
	yes | docker system prune
	sudo service docker stop
	sudo rm -rf /tmp/docker.backup/
	sudo cp -Pfr /var/lib/docker /tmp/docker.backup
	sudo rm -rf /var/lib/docker
	sudo service docker start

up: prep
	docker-compose up -d $(APP_NAME)

run: prep
	docker-compose run -d --rm -p "5000:5000" --name $(APP_NAME) --entrypoint python3.8 $(APP_NAME) run.py

down:
	@docker-compose down

restart: down run

package: prep
	zip -9rq $(APP_NAME).zip src -x '*.pyc' -x '__pycache__' -x '*.DS_Store'
	zip -uj9q $(APP_NAME).zip docker/requirements.txt

package-upload: package
	$(CMD_AWS) s3 cp --only-show-errors $(APP_NAME).zip s3://cloudformation-trivialsec/deploy-packages/$(APP_NAME)-$(COMMON_VERSION).zip
	$(CMD_AWS) s3 cp --only-show-errors deploy/nginx.conf s3://cloudformation-trivialsec/deploy-packages/nginx.conf

package-dev: common package
	$(CMD_AWS) s3 cp --only-show-errors $(APP_NAME).zip s3://cloudformation-trivialsec/deploy-packages/$(APP_NAME)-dev-$(COMMON_VERSION).zip
