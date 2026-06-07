.PHONY: help test venv up down ps logs pipeline monitor train responder api deploy deploy-down clean
help:
	@echo "make venv      - create .venv and install all deps (all layers)"
	@echo "make test      - run unit tests"
	@echo "make up         - docker compose up -d (honeypots)"
	@echo "make down       - docker compose down"
	@echo "make ps         - container status"
	@echo "make pipeline  - run the log pipeline (Weeks 1-2)"
	@echo "make monitor   - run the scapy monitor (needs sudo)"
	@echo "make train     - train the Week-3 intent classifier (macro-F1 > 0.85)"
	@echo "make responder - run the live behaviour+response daemon (needs sudo for iptables)"
	@echo "make api       - run the Week-5 dashboard/API (dev server)"
	@echo "make deploy    - one-command full stack: honeypots + portal + nginx (Day 42)"
	@echo "make deploy-down - tear down the full stack"
venv:
	python3 -m venv .venv && .venv/bin/pip install \
		-r detection/requirements.txt \
		-r behavior/requirements.txt \
		-r deception/requirements.txt \
		-r api/requirements.txt pydantic==2.7.1
train:
	.venv/bin/python behavior/train_model.py
test:
	.venv/bin/python -m pytest tests/ -v
up:
	docker compose up -d
down:
	docker compose down
ps:
	docker compose ps
logs:
	docker compose logs -f
pipeline:
	.venv/bin/python pipeline/run_pipeline.py
monitor:
	sudo .venv/bin/python detection/packet_monitor.py -i $${CAPTURE_IFACE:-eth0}
responder:
	sudo .venv/bin/python response/run_responder.py
api:
	.venv/bin/python -m api.app
deploy:
	docker compose -f docker-compose.yml -f deploy/docker-compose.portal.yml up -d --build
deploy-down:
	docker compose -f docker-compose.yml -f deploy/docker-compose.portal.yml down
clean:
	rm -f data/*.sqlite
