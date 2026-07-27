# DEAD DROP — top-level dev tasks. Typecheck + lint are build-breaking from M0 (§6).
.PHONY: all check schema gateway control-plane crypto client deploy-kit clean

all: check

check: schema gateway control-plane crypto client

schema:
	cd schema && buf lint

gateway:
	cd gateway && go vet ./... && go test ./... && CGO_ENABLED=0 go build ./...

control-plane:
	cd control-plane && composer install --no-interaction && \
		vendor/bin/phpstan analyse --no-progress

crypto:
	cd crypto && cargo test && wasm-pack build --target web

client:
	cd client && npm install --no-audit --no-fund && npm run typecheck && npm run lint && npm test

# Regenerate typed bindings for every tier from the single .proto source of truth.
gen:
	cd schema && buf generate

dev:
	cd infra && docker compose up --build

# Assemble the hardened, integrity-pinned deploy kit (web root + gateway binary + vhost + runbook)
# into deploy/. See docs/deploy-runbook.md.
deploy-kit:
	infra/build-deploy.sh

clean:
	rm -rf client/node_modules client/dist control-plane/vendor deploy
