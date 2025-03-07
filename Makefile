SHELL := /bin/bash
-include .env
export $(shell sed 's/=.*//' .env)
CONAINER_NAME	= registry.gitlab.com/trivialsec/appserver/${BUILD_ENV}
.ONESHELL:
.PHONY: help

help: ## This help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

ifndef CI_BUILD_REF
	CI_BUILD_REF = local
endif

pylint-ci: ## run pylint for CI
	pylint --exit-zero --persistent=n -f json -r n --jobs=0 --errors-only src/**/*.py > pylint.json

semgrep-sast-ci: ## run core semgrep rules for CI
	semgrep --disable-version-check -q --strict --error -o semgrep-ci.json --json --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py

semgrep-xss-ci: ## run Flask XSS semgrep rules for CI
	semgrep --disable-version-check -q --strict --error -o semgrep-flask-xss.json --json --config p/minusworld.flask-xss --lang=py src/**/*.py

build: ## Builds images using docker cli directly for CI
	@docker build --compress $(BUILD_ARGS) \
		-t $(CONAINER_NAME):$(CI_BUILD_REF) \
		--cache-from $(CONAINER_NAME):latest \
        --build-arg TRIVIALSEC_PY_LIB_VER=$(TRIVIALSEC_PY_LIB_VER) \
        --build-arg BUILD_ENV=$(BUILD_ENV) \
        --build-arg GITLAB_USER=$(GITLAB_USER) \
        --build-arg GITLAB_PASSWORD=$(GITLAB_PAT) \
		--build-arg PYTHONUNBUFFERED=1 \
        --build-arg PYTHONUTF8=1 \
        --build-arg CFLAGS='-O0' \
        --build-arg STATICBUILD=1 \
        --build-arg LC_ALL=C.UTF-8 \
        --build-arg LANG=C.UTF-8 .

push-tagged: ## Push tagged image
	docker push -q $(CONAINER_NAME):${CI_BUILD_REF}

push-ci: ## Push latest image using docker cli directly for CI
	docker tag $(CONAINER_NAME):${CI_BUILD_REF} $(CONAINER_NAME):latest
	docker push -q $(CONAINER_NAME):latest

build-ci: pull pull-base build ## Builds from latest base image

init: ## Runs tf init tf
	cd plans
	terraform init -reconfigure -upgrade=true

output:
	cd plans
	terraform output recaptcha_secret_key
	terraform output recaptcha_site_key
	terraform output appserver_linode_password

deploy: plan apply attach-firewall ## tf plan and apply -auto-approve -refresh=true

plan: init ## Runs tf validate and tf plan
	cd plans
	terraform validate
	terraform plan -no-color -out=.tfplan
	terraform show --json .tfplan | jq -r '([.resource_changes[]?.change.actions?]|flatten)|{"create":(map(select(.=="create"))|length),"update":(map(select(.=="update"))|length),"delete":(map(select(.=="delete"))|length)}' > tfplan.json

apply: ## tf apply -auto-approve -refresh=true
	cd plans
	terraform apply -auto-approve -refresh=true .tfplan

destroy: init ## tf destroy -auto-approve
	cd plans
	terraform validate
	terraform plan -destroy -no-color -out=.tfdestroy
	terraform show --json .tfdestroy | jq -r '([.resource_changes[]?.change.actions?]|flatten)|{"create":(map(select(.=="create"))|length),"update":(map(select(.=="update"))|length),"delete":(map(select(.=="delete"))|length)}' > tfdestroy.json
	terraform apply -auto-approve -destroy .tfdestroy

attach-firewall:
	curl -s -H "Content-Type: application/json" \
		-H "Authorization: Bearer ${TF_VAR_linode_token}" \
		-X POST -d '{"type": "linode", "id": $(shell curl -s -H "Authorization: Bearer ${TF_VAR_linode_token}" https://api.linode.com/v4/linode/instances | jq -r '.data[] | select(.label=="prd-api.trivialsec.com") | .id')}' \
		https://api.linode.com/v4/networking/firewalls/${LINODE_FIREWALL}/devices

#####################
# Development Only
#####################
setup: ## Creates docker networks and volumes
	@echo $(shell docker --version)
	@echo $(shell docker-compose --version)
	@pip --version
	pip install -q -U pip
	pip install -q -U setuptools wheel semgrep pylint
	pip install -q -U -r requirements.txt
	docker network create trivialsec 2>/dev/null || true

prep: ## Cleanup tmp files
	@find . -type f -name '*.pyc' -delete 2>/dev/null
	@find . -type d -name '__pycache__' -delete 2>/dev/null
	@find . -type f -name '*.DS_Store' -delete 2>/dev/null
	@rm -f **/*.zip **/*.tar **/*.tgz **/*.gz
	@rm -rf build python-libs

python-libs: prep ## download and install the trivialsec python libs locally (for IDE completions)
	yes | pip uninstall -q trivialsec-common
	git clone -q -c advice.detachedHead=false --depth 1 --branch ${TRIVIALSEC_PY_LIB_VER} --single-branch git@gitlab.com:trivialsec/python-common.git python-libs
	cd python-libs
	make install

tfinstall:
	curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
	sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(shell lsb_release -cs) main"
	sudo apt-get update
	sudo apt-get install -y terraform
	terraform -install-autocomplete || true

docker-clean: ## quick docker environment cleanup
	docker rmi $(docker images -qaf "dangling=true")
	yes | docker system prune
	sudo service docker restart

docker-purge: ## thorough docker environment cleanup
	docker rmi $(docker images -qa)
	yes | docker system prune
	sudo service docker stop
	sudo rm -rf /tmp/docker.backup/
	sudo cp -Pfr /var/lib/docker /tmp/docker.backup
	sudo rm -rf /var/lib/docker
	sudo service docker start

test-local: ## Prettier test outputs
	pylint --exit-zero -f colorized --persistent=y -r y --jobs=0 src/**/*.py
	semgrep -q --strict --timeout=0 --config=p/r2c-ci --lang=py src/**/*.py
	semgrep -q --strict --config p/minusworld.flask-xss --lang=py src/**/*.py

test-all: semgrep-xss-ci semgrep-sast-ci pylint-ci ## Run all CI tests

pull: ## pulls latest image
	docker pull -q $(CONAINER_NAME):latest

rebuild: down ## Brings down the stack and builds it anew
	docker-compose build --no-cache

debug:
	docker-compose run appserver python3 -u -d -X dev run.py

docker-login: ## login to docker cli using $GITLAB_USER and $GITLAB_PAT
	@echo $(shell [ -z "${GITLAB_PAT}" ] && echo "GITLAB_PAT missing" )
	@echo ${GITLAB_PAT} | docker login -u ${GITLAB_USER} --password-stdin registry.gitlab.com

up: prep ## Start the appserver
	docker-compose up -d

down: ## Stop the appserver
	@docker-compose down --remove-orphans

restart: down up ## restarts the appserver

setup-stripe-linux: ## Install latest stripe webhooks cli
	wget -qO - https://github.com/stripe/stripe-cli/releases/download/v1.7.8/stripe_1.7.8_linux_x86_64.tar.gz | tar xvz
	mv stripe ./bin/stripe
	./bin/stripe login

stripe-dev: ## listen for stripe webhooks
	./bin/stripe listen --forward-to localhost:5000/webhook/stripe

