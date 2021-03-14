SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
APP_NAME = appserver
LOCAL_CACHE = /tmp/trivialsec

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
	@find . -type f -name '*.pyc' -delete 2>/dev/null
	@find . -type d -name '__pycache__' -delete 2>/dev/null
	@find . -type f -name '*.DS_Store' -delete 2>/dev/null
	@rm -f **/*.zip **/*.tar **/*.tgz **/*.gz
	@rm -rf build

common: prep
	yes | pip uninstall -q trivialsec-common
	aws s3 cp --only-show-errors s3://trivialsec-assets/deploy-packages/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl
	aws s3 cp --only-show-errors s3://trivialsec-assets/deploy-packages/${COMMON_VERSION}/build.tgz build.tgz
	tar -xzvf build.tgz
	pip install -q --no-cache-dir --find-links=build/wheel --no-index trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl

common-dev: ## Install trivialsec_common lib from local build
	yes | pip uninstall -q trivialsec-common
	cp -fu $(LOCAL_CACHE)/build.tgz build.tgz
	cp -fu $(LOCAL_CACHE)/trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl trivialsec_common-$(COMMON_VERSION)-py2.py3-none-any.whl
	tar -xzvf build.tgz
	pip install -q --no-cache-dir --find-links=build/wheel --no-index trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl

install-dev:
	pip install -q -U pip setuptools pylint wheel awscli semgrep
	pip install -q -U --no-cache-dir --isolated -r ./docker/requirements.txt

lint-local:
	pylint --exit-zero -f colorized --persistent=y -r y --jobs=0 src/**/*.py
	semgrep -q --strict --timeout=0 --config=p/ci --lang=py src/**/*.py
	semgrep -q --strict --config p/minusworld.flask-xss --lang=py src/**/*.py

lint:
	pylint --persistent=n -f json -r n --jobs=0 --errors-only src/**/*.py > pylint.json
	semgrep --disable-version-check -q --strict --error -o semgrep-ci.json --json --timeout=0 --config=p/ci --lang=py src/**/*.py
	semgrep --disable-version-check -q --strict --error -o semgrep-flask-xss.json --json --config p/minusworld.flask-xss --lang=py src/**/*.py

stripe-dev:
	stripe listen --forward-to localhost:5000/webhook/stripe

build: prep package-dev ## Build compressed container
	docker-compose build --compress

buildnc: prep package-dev ## Clean build docker
	docker-compose build --no-cache --compress

rebuild: down build

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
	docker-compose up -d $(APP_NAME)

run: prep
	docker-compose run -d --rm -p "5000:5000" --name $(APP_NAME) --entrypoint python3.8 $(APP_NAME) run.py

down: ## Stop the app
	@docker-compose down

restart: down run

package: prep
	tar --exclude '*.pyc' --exclude '__pycache__' --exclude '*.DS_Store' -cf $(APP_NAME).tar src
	tar -rf $(APP_NAME).tar -C deploy requirements.txt
	gzip appserver.tar

package-upload:
	$(CMD_AWS) s3 cp --only-show-errors $(APP_NAME).tar.gz s3://trivialsec-assets/deploy-packages/${COMMON_VERSION}/$(APP_NAME).tar.gz
	$(CMD_AWS) s3 cp --only-show-errors deploy/nginx.conf s3://trivialsec-assets/deploy-packages/${COMMON_VERSION}/$(APP_NAME)-nginx.conf

package-dev: prep common-dev
	tar --exclude '.flaskenv' --exclude '*.pyc' --exclude '__pycache__' --exclude '*.DS_Store' -cf $(APP_NAME).tar src
	tar -rf $(APP_NAME).tar -C docker requirements.txt
	gzip appserver.tar
	$(CMD_AWS) s3 cp --only-show-errors $(APP_NAME).tar.gz s3://trivialsec-assets/dev/${COMMON_VERSION}/$(APP_NAME).tar.gz
