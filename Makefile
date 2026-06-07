.PHONY: help test venv up down ps logs pipeline monitor train analyze clean
help:
	@echo "make venv     - create .venv and install all deps (detection+behavior+deception)"
	@echo "make test     - run unit tests"
	@echo "make up        - docker compose up -d (honeypots)"
	@echo "make down     - docker compose down"
	@echo "make ps        - container status"
	@echo "make pipeline - run the log pipeline"
	@echo "make monitor  - run the scapy monitor (needs sudo)"
	@echo "make train    - train the Week-3 intent classifier (macro-F1 > 0.85)"
venv:
	python3 -m venv .venv && .venv/bin/pip install \
		-r detection/requirements.txt \
		-r behavior/requirements.txt \
		-r deception/requirements.txt
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
clean:
	rm -f data/*.sqlite
