.PHONY: test verify clean-machine-macos broker-test release-broker-test persona-eval persona-eval-verify persona-eval-fixtures persona-qualification-test persona-qualification-adapter-stage persona-qualify persona-qualification-status persona-qualification-verify persona-qualification-public-verify reputation-report reputation-verify continuity-import-status continuity-import-verify continuity-import-admit continuity-import-recover deploy doctor status smoke smoke-all gh-auth-repair privacy-scan tick-diagnostic tick-forge tick-overwatch tick-learning queue-health worker-status autonomy-status release-health release-dry-run release-broker-status release-prepare release-apply release-receipt-verify learning-smoke learning-backfill learning-review learning-digest learning-prepare-promotion learning-apply-promotion install-supervisor uninstall-supervisor install-guide-gateway install-protected-broker uninstall-protected-broker install-protected-release-broker uninstall-protected-release-broker install-protected-release-owner-gateway uninstall-protected-release-owner-gateway

INSTANCE ?=
PRODUCT_PYTHON ?= uv run --frozen python
OFFLINE_PRODUCT_PYTHON ?= uv run --frozen --offline python
TEST_PATH ?= /opt/homebrew/opt/openssl@3/bin:/opt/homebrew/bin:/usr/local/opt/openssl@3/bin:/usr/local/bin:$(PATH)
PERSONA_EVAL_RUN ?=
PERSONA_EVAL_REPORT ?=
PERSONA_QUALIFICATION_PRIVATE_ROOT ?=
PERSONA_QUALIFICATION_CANDIDATE_COMMAND ?=
PERSONA_QUALIFICATION_JUDGE_COMMAND ?=
PERSONA_QUALIFICATION_RUN_ID ?=
PERSONA_QUALIFICATION_TIMEOUT ?=
PERSONA_QUALIFICATION_MAX_CALLS ?=
PERSONA_QUALIFICATION_MAX_TOTAL_TOKENS ?=
PERSONA_QUALIFICATION_MAX_WALL_SECONDS ?=
PERSONA_QUALIFICATION_MAX_AGE_SECONDS ?=
PERSONA_QUALIFICATION_SCENARIOS ?=
PERSONA_QUALIFICATION_RUBRIC ?=
PERSONA_QUALIFICATION_ADAPTER_DEST ?=
PERSONA_QUALIFICATION_PYTHON ?=
PERSONA_QUALIFICATION_JUDGE_PROVIDER ?= openai
PERSONA_QUALIFICATION_JUDGE_MODEL ?=
PERSONA_QUALIFICATION_JUDGE_REASONING_EFFORT ?= xhigh
PERSONA_QUALIFICATION_CANDIDATE_API_KEY_ENV ?=
PERSONA_QUALIFICATION_JUDGE_API_KEY_ENV ?=
REPUTATION_LEDGER ?=
REPUTATION_REPORT ?=
REPUTATION_PUBLIC_KEY ?=
REPUTATION_OBSERVER_POLICY ?=
CONTINUITY_ENVELOPE ?=
BROKER_SLUG ?=
BROKER_CONFIG ?=
BROKER_GITHUB_APP_PRIVATE_KEY ?=
BROKER_RECEIPT_PRIVATE_KEY ?=
BROKER_RECEIPT_PUBLIC_KEY ?=
BROKER_PYTHON ?=
BROKER_USER ?=
BROKER_REQUESTER_USER ?=
BROKER_SUBMIT_GROUP ?=
RELEASE_BROKER_SLUG ?=
RELEASE_BROKER_CONFIG ?=
RELEASE_BROKER_GITHUB_APP_PRIVATE_KEY ?=
RELEASE_BROKER_OWNER_ASSERTION_PUBLIC_KEY ?=
RELEASE_BROKER_RECEIPT_PRIVATE_KEY ?=
RELEASE_BROKER_RECEIPT_PUBLIC_KEY ?=
RELEASE_BROKER_PYTHON ?=
RELEASE_BROKER_USER ?=
RELEASE_BROKER_REQUESTER_USER ?=
RELEASE_BROKER_SUBMIT_GROUP ?=
RELEASE_OWNER_GATEWAY_SLUG ?=
RELEASE_OWNER_GATEWAY_SIGNER_CONFIG ?=
RELEASE_OWNER_GATEWAY_DISCORD_SOURCE_CONFIG ?=
RELEASE_OWNER_GATEWAY_SIGNING_PRIVATE_KEY ?=
RELEASE_OWNER_GATEWAY_SIGNING_PUBLIC_KEY ?=
RELEASE_OWNER_GATEWAY_DISCORD_BOT_TOKEN ?=
RELEASE_OWNER_GATEWAY_PYTHON ?=
RELEASE_OWNER_GATEWAY_SIGNER_USER ?=
RELEASE_OWNER_GATEWAY_REQUESTER_USER ?=
RELEASE_OWNER_GATEWAY_SUBMIT_GROUP ?=
RELEASE_BUNDLE ?=
RELEASE_APPROVAL_FILE ?=
RELEASE_OWNER_ASSERTION ?=
RELEASE_PACKET ?=
RELEASE_RECEIPT ?=

test:
	@PATH="$(TEST_PATH)" uv run --frozen pytest -q

verify:
	@uv run --frozen python -m compileall -q broker owner_gateway qualification_adapters qualification_attestor qualification_verifier release_broker runtime_plugins scripts tests
	@uv run --frozen python scripts/privacy-scan.py .
	@PATH="$(TEST_PATH)" uv run --frozen pytest -q
	@git diff --check
	@git diff --cached --check
	@git log -1 --check --format=

clean-machine-macos:
	@./scripts/macos-clean-machine-check.sh

broker-test:
	@PATH="$(TEST_PATH)" uv run --frozen pytest -q tests/test_broker_*.py tests/test_comment_templates.py tests/test_protected_action_packets.py

release-broker-test:
	@PATH="$(TEST_PATH)" uv run --frozen pytest -q tests/test_release_broker_*.py tests/test_release_owner_*.py tests/test_release_packets.py tests/test_release_runtime_approval.py tests/test_release_approval_plugin.py

persona-eval:
	@test -n "$(PERSONA_EVAL_RUN)" || (echo "usage: make persona-eval PERSONA_EVAL_RUN=/private/run.json [PERSONA_EVAL_REPORT=/public/report.json]" >&2; exit 2)
	@$(PRODUCT_PYTHON) scripts/john-lomein-persona-eval.py evaluate --run "$(PERSONA_EVAL_RUN)" --pretty $(if $(strip $(PERSONA_EVAL_REPORT)),--output "$(PERSONA_EVAL_REPORT)",)

persona-eval-verify:
	@test -n "$(PERSONA_EVAL_REPORT)" || (echo "usage: make persona-eval-verify PERSONA_EVAL_REPORT=/public/report.json [PERSONA_EVAL_RUN=/private/run.json]" >&2; exit 2)
	@$(PRODUCT_PYTHON) scripts/john-lomein-persona-eval.py verify --report "$(PERSONA_EVAL_REPORT)" --pretty $(if $(strip $(PERSONA_EVAL_RUN)),--run "$(PERSONA_EVAL_RUN)",)

persona-eval-fixtures:
	@PATH="$(TEST_PATH)" uv run --frozen pytest -q tests/test_persona_evaluator.py

persona-qualification-test:
	@PATH="$(TEST_PATH)" uv run --frozen pytest -q \
		tests/test_doctor_protected_qualification.py \
		tests/test_persona_evaluator.py \
		tests/test_persona_qualification*.py \
		tests/test_openai_qualification_adapter.py \
		tests/test_stage_persona_qualification_openai_adapter.py

persona-qualification-adapter-stage: _require_instance
	@test -n "$(PERSONA_QUALIFICATION_ADAPTER_DEST)" || (echo "missing PERSONA_QUALIFICATION_ADAPTER_DEST" >&2; exit 2)
	@test -n "$(PERSONA_QUALIFICATION_PYTHON)" || (echo "missing PERSONA_QUALIFICATION_PYTHON" >&2; exit 2)
	@test -n "$(PERSONA_QUALIFICATION_JUDGE_MODEL)" || (echo "missing PERSONA_QUALIFICATION_JUDGE_MODEL" >&2; exit 2)
	@$(OFFLINE_PRODUCT_PYTHON) scripts/stage-persona-qualification-openai-adapter.py \
		--instance "$(INSTANCE)" \
		--destination "$(PERSONA_QUALIFICATION_ADAPTER_DEST)" \
		--python "$(PERSONA_QUALIFICATION_PYTHON)" \
		--judge-provider "$(PERSONA_QUALIFICATION_JUDGE_PROVIDER)" \
		--judge-model "$(PERSONA_QUALIFICATION_JUDGE_MODEL)" \
		--judge-reasoning-effort "$(PERSONA_QUALIFICATION_JUDGE_REASONING_EFFORT)" $(if $(strip $(PERSONA_QUALIFICATION_CANDIDATE_API_KEY_ENV)),--candidate-api-key-env "$(PERSONA_QUALIFICATION_CANDIDATE_API_KEY_ENV)",) $(if $(strip $(PERSONA_QUALIFICATION_JUDGE_API_KEY_ENV)),--judge-api-key-env "$(PERSONA_QUALIFICATION_JUDGE_API_KEY_ENV)",)

persona-qualify: _require_instance
	@test -n "$(PERSONA_QUALIFICATION_PRIVATE_ROOT)" || (echo "missing PERSONA_QUALIFICATION_PRIVATE_ROOT" >&2; exit 2)
	@test -n "$(PERSONA_QUALIFICATION_CANDIDATE_COMMAND)" || (echo "missing PERSONA_QUALIFICATION_CANDIDATE_COMMAND" >&2; exit 2)
	@test -n "$(PERSONA_QUALIFICATION_JUDGE_COMMAND)" || (echo "missing PERSONA_QUALIFICATION_JUDGE_COMMAND" >&2; exit 2)
	@$(PRODUCT_PYTHON) scripts/john-lomein-persona-qualification.py run \
		--instance "$(INSTANCE)" \
		--private-root "$(PERSONA_QUALIFICATION_PRIVATE_ROOT)" \
		--candidate-command "$(PERSONA_QUALIFICATION_CANDIDATE_COMMAND)" \
		--judge-command "$(PERSONA_QUALIFICATION_JUDGE_COMMAND)" $(if $(strip $(PERSONA_QUALIFICATION_RUN_ID)),--run-id "$(PERSONA_QUALIFICATION_RUN_ID)",) $(if $(strip $(PERSONA_QUALIFICATION_TIMEOUT)),--timeout "$(PERSONA_QUALIFICATION_TIMEOUT)",) $(if $(strip $(PERSONA_QUALIFICATION_MAX_CALLS)),--max-calls "$(PERSONA_QUALIFICATION_MAX_CALLS)",) $(if $(strip $(PERSONA_QUALIFICATION_MAX_TOTAL_TOKENS)),--max-total-tokens "$(PERSONA_QUALIFICATION_MAX_TOTAL_TOKENS)",) $(if $(strip $(PERSONA_QUALIFICATION_MAX_WALL_SECONDS)),--max-wall-seconds "$(PERSONA_QUALIFICATION_MAX_WALL_SECONDS)",) $(if $(strip $(PERSONA_QUALIFICATION_MAX_AGE_SECONDS)),--max-age-seconds "$(PERSONA_QUALIFICATION_MAX_AGE_SECONDS)",) $(if $(strip $(PERSONA_QUALIFICATION_SCENARIOS)),--scenarios "$(PERSONA_QUALIFICATION_SCENARIOS)",) $(if $(strip $(PERSONA_QUALIFICATION_RUBRIC)),--rubric "$(PERSONA_QUALIFICATION_RUBRIC)",)

persona-qualification-status: _require_instance
	@$(PRODUCT_PYTHON) scripts/john-lomein-persona-qualification.py status \
		--instance "$(INSTANCE)" $(if $(strip $(PERSONA_QUALIFICATION_SCENARIOS)),--scenarios "$(PERSONA_QUALIFICATION_SCENARIOS)",) $(if $(strip $(PERSONA_QUALIFICATION_RUBRIC)),--rubric "$(PERSONA_QUALIFICATION_RUBRIC)",)

persona-qualification-verify: _require_instance
	@test -n "$(PERSONA_QUALIFICATION_PRIVATE_ROOT)" || (echo "missing PERSONA_QUALIFICATION_PRIVATE_ROOT" >&2; exit 2)
	@$(PRODUCT_PYTHON) scripts/john-lomein-persona-qualification.py verify \
		--instance "$(INSTANCE)" \
		--private-root "$(PERSONA_QUALIFICATION_PRIVATE_ROOT)" $(if $(strip $(PERSONA_QUALIFICATION_SCENARIOS)),--scenarios "$(PERSONA_QUALIFICATION_SCENARIOS)",) $(if $(strip $(PERSONA_QUALIFICATION_RUBRIC)),--rubric "$(PERSONA_QUALIFICATION_RUBRIC)",)

persona-qualification-public-verify:
	@$(OFFLINE_PRODUCT_PYTHON) scripts/john-lomein-persona-trust.py

reputation-report:
	@test -n "$(REPUTATION_LEDGER)" || (echo "missing REPUTATION_LEDGER" >&2; exit 2)
	@test -n "$(REPUTATION_PUBLIC_KEY)" || (echo "missing REPUTATION_PUBLIC_KEY" >&2; exit 2)
	@test -n "$(REPUTATION_OBSERVER_POLICY)" || (echo "missing REPUTATION_OBSERVER_POLICY" >&2; exit 2)
	@$(PRODUCT_PYTHON) scripts/john-lomein-reputation.py build --ledger "$(REPUTATION_LEDGER)" --public-key "$(REPUTATION_PUBLIC_KEY)" --observer-policy "$(REPUTATION_OBSERVER_POLICY)" --pretty $(if $(strip $(REPUTATION_REPORT)),--output "$(REPUTATION_REPORT)",)

reputation-verify:
	@test -n "$(REPUTATION_REPORT)" || (echo "missing REPUTATION_REPORT" >&2; exit 2)
	@test -n "$(REPUTATION_LEDGER)" || (echo "missing REPUTATION_LEDGER" >&2; exit 2)
	@test -n "$(REPUTATION_PUBLIC_KEY)" || (echo "missing REPUTATION_PUBLIC_KEY" >&2; exit 2)
	@test -n "$(REPUTATION_OBSERVER_POLICY)" || (echo "missing REPUTATION_OBSERVER_POLICY" >&2; exit 2)
	@$(PRODUCT_PYTHON) scripts/john-lomein-reputation.py verify --report "$(REPUTATION_REPORT)" --ledger "$(REPUTATION_LEDGER)" --public-key "$(REPUTATION_PUBLIC_KEY)" --observer-policy "$(REPUTATION_OBSERVER_POLICY)" --pretty

continuity-import-status: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; $(PRODUCT_PYTHON) scripts/john_lomein_continuity_importer.py --runtime-home "$$BOT_HERMES_HOME" status'

continuity-import-verify: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; $(PRODUCT_PYTHON) scripts/john_lomein_continuity_importer.py --runtime-home "$$BOT_HERMES_HOME" verify'

continuity-import-recover: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; $(PRODUCT_PYTHON) scripts/john_lomein_continuity_importer.py --runtime-home "$$BOT_HERMES_HOME" recover'

continuity-import-admit: _require_instance
	@test -n "$(CONTINUITY_ENVELOPE)" || (echo "missing CONTINUITY_ENVELOPE=/absolute/signed-envelope.json" >&2; exit 2)
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; $(PRODUCT_PYTHON) scripts/john_lomein_continuity_importer.py --runtime-home "$$BOT_HERMES_HOME" admit --envelope "$(CONTINUITY_ENVELOPE)"'

_require_instance:
	@test -n "$(INSTANCE)" || (echo "usage: make <target> INSTANCE=/path/to/instance" >&2; exit 2)
	@if [ -n "$(JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT)" ]; then \
		test -f "$(JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT)" || (echo "missing setup manifest snapshot" >&2; exit 2); \
	else \
		test -f "$(INSTANCE)/instance.yaml" || test -f "$(INSTANCE)/bot.yaml" || (echo "missing instance.yaml or bot.yaml in $(INSTANCE)" >&2; exit 2); \
	fi

deploy: _require_instance
	@bash scripts/deploy-instance.sh "$(INSTANCE)"

doctor: _require_instance
	@$(PRODUCT_PYTHON) scripts/doctor-instance.py "$(INSTANCE)"

status: _require_instance
	@$(OFFLINE_PRODUCT_PYTHON) scripts/john-lomein-orient.py "$(INSTANCE)"

gh-auth-repair: _require_instance
	@$(PRODUCT_PYTHON) scripts/repair-profile-gh-auth.py "$(INSTANCE)"

smoke: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; export HERMES_HOME="$$BOT_HERMES_HOME" JOHN_LOMEIN_INSTANCE_HERMES_HOME="$$BOT_HERMES_HOME" HERMES_MANAGED_DIR="$$BOT_HERMES_MANAGED_ROOT/$$BOT_MAINTAINER_PROFILE" HERMES_REAL_HOME="$${HERMES_REAL_HOME:-$$HOME}" JOHN_LOMEIN_AUTH_AUTHORITY_HOME="$${JOHN_LOMEIN_AUTH_AUTHORITY_HOME:-$${HERMES_REAL_HOME:-$$HOME}/.hermes}" BOT_MODEL_PROVIDER BOT_FALLBACK_PROVIDER BOT_MODEL_MEMORY_ISOLATION BOT_STEWARD_PRIVATE_ROOT BOT_STEWARD_PROJECTION_ROOT BOT_LOCAL; unset MNEMOSYNE_DATA_DIR; marker="$$BOT_SLUG-maintainer-ok"; $(PRODUCT_PYTHON) "$$BOT_HERMES_HOME/scripts/john_lomein_model_isolation.py" --profile "$$BOT_MAINTAINER_PROFILE" -- hermes -p "$$BOT_MAINTAINER_PROFILE" chat -q "Reply with exactly: $$marker" -Q 2>/dev/null | grep -F "$$marker"'

smoke-all: _require_instance
	@bash -c 'set -euo pipefail; eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; export HERMES_HOME="$$BOT_HERMES_HOME" JOHN_LOMEIN_INSTANCE_HERMES_HOME="$$BOT_HERMES_HOME" HERMES_REAL_HOME="$${HERMES_REAL_HOME:-$$HOME}" JOHN_LOMEIN_AUTH_AUTHORITY_HOME="$${JOHN_LOMEIN_AUTH_AUTHORITY_HOME:-$${HERMES_REAL_HOME:-$$HOME}/.hermes}" BOT_MODEL_PROVIDER BOT_FALLBACK_PROVIDER BOT_MODEL_MEMORY_ISOLATION BOT_STEWARD_PRIVATE_ROOT BOT_STEWARD_PROJECTION_ROOT BOT_LOCAL; unset MNEMOSYNE_DATA_DIR; roles="maintainer forge guide overwatch"; if [ "$${BOT_LEARNING_ENABLED:-1}" = "1" ]; then roles="$$roles learning_steward"; fi; for role in $$roles; do pvar="BOT_$$(printf "%s" "$$role" | tr a-z A-Z)_PROFILE"; p="$${!pvar}"; export HERMES_MANAGED_DIR="$$BOT_HERMES_MANAGED_ROOT/$$p"; marker="$$BOT_SLUG-$$role-ok"; $(PRODUCT_PYTHON) "$$BOT_HERMES_HOME/scripts/john_lomein_model_isolation.py" --profile "$$p" -- hermes -p "$$p" chat -q "Reply with exactly: $$marker" -Q 2>/dev/null | grep -F "$$marker"; done'

tick-diagnostic: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; export HERMES_HOME="$$BOT_HERMES_HOME" JOHN_LOMEIN_INSTANCE_HERMES_HOME="$$BOT_HERMES_HOME"; unset MNEMOSYNE_DATA_DIR; bash "$$BOT_HERMES_HOME/scripts/john-lomein-diagnostic-tick.sh"'

tick-forge: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; export HERMES_HOME="$$BOT_HERMES_HOME" JOHN_LOMEIN_INSTANCE_HERMES_HOME="$$BOT_HERMES_HOME"; unset MNEMOSYNE_DATA_DIR; . "$$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"; "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john-lomein-worker.py" run forge'

tick-overwatch: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; export HERMES_HOME="$$BOT_HERMES_HOME" JOHN_LOMEIN_INSTANCE_HERMES_HOME="$$BOT_HERMES_HOME"; unset MNEMOSYNE_DATA_DIR; . "$$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"; "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john-lomein-overwatch-scan.py"'

tick-learning: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; export HERMES_HOME="$$BOT_HERMES_HOME" JOHN_LOMEIN_INSTANCE_HERMES_HOME="$$BOT_HERMES_HOME" MNEMOSYNE_DATA_DIR="$$BOT_STEWARD_PRIVATE_ROOT/mnemosyne/data"; . "$$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"; "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john-lomein-learning-steward.py" reconcile --mode manual --json'

learning-smoke: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; export HERMES_HOME="$$BOT_HERMES_HOME" JOHN_LOMEIN_INSTANCE_HERMES_HOME="$$BOT_HERMES_HOME" MNEMOSYNE_DATA_DIR="$$BOT_STEWARD_PRIVATE_ROOT/mnemosyne/data" JOHN_LOMEIN_PRODUCT_ROOT="$$(pwd)"; . "$$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"; "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john-lomein-learning-steward.py" smoke --json'

learning-backfill: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; export HERMES_HOME="$$BOT_HERMES_HOME" JOHN_LOMEIN_INSTANCE_HERMES_HOME="$$BOT_HERMES_HOME" MNEMOSYNE_DATA_DIR="$$BOT_STEWARD_PRIVATE_ROOT/mnemosyne/data" JOHN_LOMEIN_PRODUCT_ROOT="$$(pwd)"; . "$$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"; "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john-lomein-learning-steward.py" backfill-worker-logs --json'

learning-review: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; export HERMES_HOME="$$BOT_HERMES_HOME" JOHN_LOMEIN_INSTANCE_HERMES_HOME="$$BOT_HERMES_HOME" MNEMOSYNE_DATA_DIR="$$BOT_STEWARD_PRIVATE_ROOT/mnemosyne/data" JOHN_LOMEIN_PRODUCT_ROOT="$$(pwd)"; . "$$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"; "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john-lomein-learning-steward.py" review-candidates --json'

learning-digest:
	@$(PRODUCT_PYTHON) scripts/john-lomein-cross-instance-learning-digest.py

learning-prepare-promotion: _require_instance
	@test -n "$(CANDIDATE)" || (echo "usage: make learning-prepare-promotion INSTANCE=/path CANDIDATE=<id> TARGET=docs/foo.md PROPOSAL='text'" >&2; exit 2)
	@test -n "$(TARGET)" || (echo "missing TARGET" >&2; exit 2)
	@test -n "$(PROPOSAL)" || (echo "missing PROPOSAL" >&2; exit 2)
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; export HERMES_HOME="$$BOT_HERMES_HOME" JOHN_LOMEIN_INSTANCE_HERMES_HOME="$$BOT_HERMES_HOME" MNEMOSYNE_DATA_DIR="$$BOT_STEWARD_PRIVATE_ROOT/mnemosyne/data" JOHN_LOMEIN_PRODUCT_ROOT="$$(pwd)"; . "$$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"; "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john-lomein-learning-steward.py" prepare-promotion --candidate "$${CANDIDATE:-$(CANDIDATE)}" --target "$${TARGET:-$(TARGET)}" --proposal-text "$${PROPOSAL:-$(PROPOSAL)}" --json'

learning-apply-promotion: _require_instance
	@test -n "$(REQUEST)" || (echo "usage: JOHN_LOMEIN_TRUST_ASSERTION=<signed-owner-assertion> make learning-apply-promotion INSTANCE=/path REQUEST=<id> APPROVAL='exact generated phrase'" >&2; exit 2)
	@test -n "$(APPROVAL)" || (echo "missing APPROVAL" >&2; exit 2)
	@test -n "$${JOHN_LOMEIN_TRUST_ASSERTION:-}" || (echo "missing JOHN_LOMEIN_TRUST_ASSERTION" >&2; exit 2)
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; export HERMES_HOME="$$BOT_HERMES_HOME" JOHN_LOMEIN_INSTANCE_HERMES_HOME="$$BOT_HERMES_HOME" MNEMOSYNE_DATA_DIR="$$BOT_STEWARD_PRIVATE_ROOT/mnemosyne/data" JOHN_LOMEIN_PRODUCT_ROOT="$$(pwd)"; . "$$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"; "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john-lomein-learning-steward.py" apply-promotion --request "$${REQUEST:-$(REQUEST)}" --approval "$${APPROVAL:-$(APPROVAL)}" --json'

queue-health: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; export HERMES_HOME="$$BOT_HERMES_HOME" JOHN_LOMEIN_INSTANCE_HERMES_HOME="$$BOT_HERMES_HOME"; unset MNEMOSYNE_DATA_DIR; . "$$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"; "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john-lomein-queue-health.py"'

worker-status: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; export HERMES_HOME="$$BOT_HERMES_HOME" JOHN_LOMEIN_INSTANCE_HERMES_HOME="$$BOT_HERMES_HOME"; unset MNEMOSYNE_DATA_DIR; . "$$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"; "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john-lomein-worker.py" status'

autonomy-status: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john_lomein_autonomy.py" --runtime-home "$$BOT_HERMES_HOME" status'

release-health: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; export HERMES_HOME="$$BOT_HERMES_HOME" JOHN_LOMEIN_INSTANCE_HERMES_HOME="$$BOT_HERMES_HOME"; unset MNEMOSYNE_DATA_DIR; . "$$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"; "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john-lomein-release-bundler.py" --signal'

release-dry-run: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; export HERMES_HOME="$$BOT_HERMES_HOME" JOHN_LOMEIN_INSTANCE_HERMES_HOME="$$BOT_HERMES_HOME"; unset MNEMOSYNE_DATA_DIR; . "$$BOT_HERMES_HOME/scripts/john-lomein-auth-env.sh"; "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john-lomein-release-executor.py" --dry-run'

release-broker-status: _require_instance
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john-lomein-release-approve.py" status'

release-prepare: _require_instance
	@test -n "$(RELEASE_BUNDLE)" || (echo "missing RELEASE_BUNDLE" >&2; exit 2)
	@test -n "$(RELEASE_APPROVAL_FILE)" || (echo "missing RELEASE_APPROVAL_FILE" >&2; exit 2)
	@test -n "$(RELEASE_OWNER_ASSERTION)" || (echo "missing RELEASE_OWNER_ASSERTION" >&2; exit 2)
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; test "$${BOT_MUTATION_ENABLED:-0}" = "1" || (echo "runtime mutation is disabled" >&2; exit 2); test "$${BOT_PROTECTED_RELEASE_BROKER_ENABLED:-0}" = "1" || (echo "protected release broker is disabled by the instance manifest" >&2; exit 2); "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john_lomein_release_packets.py" prepare --bundle "$(RELEASE_BUNDLE)" --approval-file "$(RELEASE_APPROVAL_FILE)" --owner-assertion "$(RELEASE_OWNER_ASSERTION)" --runtime-home "$$BOT_HERMES_HOME"'

release-apply: _require_instance
	@test -n "$(RELEASE_PACKET)" || (echo "missing RELEASE_PACKET" >&2; exit 2)
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; test "$${BOT_MUTATION_ENABLED:-0}" = "1" || (echo "runtime mutation is disabled" >&2; exit 2); test "$${BOT_PROTECTED_RELEASE_BROKER_ENABLED:-0}" = "1" || (echo "protected release broker is disabled by the instance manifest" >&2; exit 2); "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john-lomein-release-submit.py" submit --packet "$(RELEASE_PACKET)" --runtime-home "$$BOT_HERMES_HOME"'

release-receipt-verify: _require_instance
	@test -n "$(RELEASE_PACKET)" || (echo "missing RELEASE_PACKET" >&2; exit 2)
	@test -n "$(RELEASE_RECEIPT)" || (echo "missing RELEASE_RECEIPT" >&2; exit 2)
	@bash -c 'eval "$$($(PRODUCT_PYTHON) scripts/read-instance-env.py "$(INSTANCE)")"; "$${HERMES_PYTHON:-python3}" "$$BOT_HERMES_HOME/scripts/john-lomein-release-submit.py" verify --packet "$(RELEASE_PACKET)" --receipt "$(RELEASE_RECEIPT)" --runtime-home "$$BOT_HERMES_HOME"'

install-supervisor: _require_instance
	@bash scripts/install-runtime-supervisor.sh "$(INSTANCE)"

uninstall-supervisor: _require_instance
	@bash scripts/uninstall-runtime-supervisor.sh "$(INSTANCE)"

install-guide-gateway: _require_instance
	@bash scripts/install-guide-gateway.sh "$(INSTANCE)"

install-protected-broker:
	@test -n "$(BROKER_SLUG)" || (echo "missing BROKER_SLUG" >&2; exit 2)
	@test -n "$(BROKER_CONFIG)" || (echo "missing BROKER_CONFIG" >&2; exit 2)
	@test -n "$(BROKER_GITHUB_APP_PRIVATE_KEY)" || (echo "missing BROKER_GITHUB_APP_PRIVATE_KEY" >&2; exit 2)
	@test -n "$(BROKER_RECEIPT_PRIVATE_KEY)" || (echo "missing BROKER_RECEIPT_PRIVATE_KEY" >&2; exit 2)
	@test -n "$(BROKER_RECEIPT_PUBLIC_KEY)" || (echo "missing BROKER_RECEIPT_PUBLIC_KEY" >&2; exit 2)
	@test -n "$(BROKER_PYTHON)" || (echo "missing BROKER_PYTHON" >&2; exit 2)
	@test -n "$(BROKER_USER)" || (echo "missing BROKER_USER" >&2; exit 2)
	@test -n "$(BROKER_REQUESTER_USER)" || (echo "missing BROKER_REQUESTER_USER" >&2; exit 2)
	@test -n "$(BROKER_SUBMIT_GROUP)" || (echo "missing BROKER_SUBMIT_GROUP" >&2; exit 2)
	@/bin/bash scripts/install-protected-broker.sh \
		--slug "$(BROKER_SLUG)" \
		--config "$(BROKER_CONFIG)" \
		--github-app-private-key "$(BROKER_GITHUB_APP_PRIVATE_KEY)" \
		--receipt-private-key "$(BROKER_RECEIPT_PRIVATE_KEY)" \
		--receipt-public-key "$(BROKER_RECEIPT_PUBLIC_KEY)" \
		--python "$(BROKER_PYTHON)" \
		--broker-user "$(BROKER_USER)" \
		--requester-user "$(BROKER_REQUESTER_USER)" \
		--submit-group "$(BROKER_SUBMIT_GROUP)"

uninstall-protected-broker:
	@test -n "$(BROKER_SLUG)" || (echo "missing BROKER_SLUG" >&2; exit 2)
	@/bin/bash scripts/uninstall-protected-broker.sh --slug "$(BROKER_SLUG)"

install-protected-release-broker:
	@test -n "$(RELEASE_BROKER_SLUG)" || (echo "missing RELEASE_BROKER_SLUG" >&2; exit 2)
	@test -n "$(RELEASE_BROKER_CONFIG)" || (echo "missing RELEASE_BROKER_CONFIG" >&2; exit 2)
	@test -n "$(RELEASE_BROKER_GITHUB_APP_PRIVATE_KEY)" || (echo "missing RELEASE_BROKER_GITHUB_APP_PRIVATE_KEY" >&2; exit 2)
	@test -n "$(RELEASE_BROKER_OWNER_ASSERTION_PUBLIC_KEY)" || (echo "missing RELEASE_BROKER_OWNER_ASSERTION_PUBLIC_KEY" >&2; exit 2)
	@test -n "$(RELEASE_BROKER_RECEIPT_PRIVATE_KEY)" || (echo "missing RELEASE_BROKER_RECEIPT_PRIVATE_KEY" >&2; exit 2)
	@test -n "$(RELEASE_BROKER_RECEIPT_PUBLIC_KEY)" || (echo "missing RELEASE_BROKER_RECEIPT_PUBLIC_KEY" >&2; exit 2)
	@test -n "$(RELEASE_BROKER_PYTHON)" || (echo "missing RELEASE_BROKER_PYTHON" >&2; exit 2)
	@test -n "$(RELEASE_BROKER_USER)" || (echo "missing RELEASE_BROKER_USER" >&2; exit 2)
	@test -n "$(RELEASE_BROKER_REQUESTER_USER)" || (echo "missing RELEASE_BROKER_REQUESTER_USER" >&2; exit 2)
	@test -n "$(RELEASE_BROKER_SUBMIT_GROUP)" || (echo "missing RELEASE_BROKER_SUBMIT_GROUP" >&2; exit 2)
	@/bin/bash scripts/install-protected-release-broker.sh \
		--slug "$(RELEASE_BROKER_SLUG)" \
		--config "$(RELEASE_BROKER_CONFIG)" \
		--github-app-private-key "$(RELEASE_BROKER_GITHUB_APP_PRIVATE_KEY)" \
		--owner-assertion-public-key "$(RELEASE_BROKER_OWNER_ASSERTION_PUBLIC_KEY)" \
		--receipt-private-key "$(RELEASE_BROKER_RECEIPT_PRIVATE_KEY)" \
		--receipt-public-key "$(RELEASE_BROKER_RECEIPT_PUBLIC_KEY)" \
		--python "$(RELEASE_BROKER_PYTHON)" \
		--broker-user "$(RELEASE_BROKER_USER)" \
		--requester-user "$(RELEASE_BROKER_REQUESTER_USER)" \
		--submit-group "$(RELEASE_BROKER_SUBMIT_GROUP)"

uninstall-protected-release-broker:
	@test -n "$(RELEASE_BROKER_SLUG)" || (echo "missing RELEASE_BROKER_SLUG" >&2; exit 2)
	@/bin/bash scripts/uninstall-protected-release-broker.sh --slug "$(RELEASE_BROKER_SLUG)"

install-protected-release-owner-gateway:
	@test -n "$(RELEASE_OWNER_GATEWAY_SLUG)" || (echo "missing RELEASE_OWNER_GATEWAY_SLUG" >&2; exit 2)
	@test -n "$(RELEASE_OWNER_GATEWAY_SIGNER_CONFIG)" || (echo "missing RELEASE_OWNER_GATEWAY_SIGNER_CONFIG" >&2; exit 2)
	@test -n "$(RELEASE_OWNER_GATEWAY_DISCORD_SOURCE_CONFIG)" || (echo "missing RELEASE_OWNER_GATEWAY_DISCORD_SOURCE_CONFIG" >&2; exit 2)
	@test -n "$(RELEASE_OWNER_GATEWAY_SIGNING_PRIVATE_KEY)" || (echo "missing RELEASE_OWNER_GATEWAY_SIGNING_PRIVATE_KEY" >&2; exit 2)
	@test -n "$(RELEASE_OWNER_GATEWAY_SIGNING_PUBLIC_KEY)" || (echo "missing RELEASE_OWNER_GATEWAY_SIGNING_PUBLIC_KEY" >&2; exit 2)
	@test -n "$(RELEASE_OWNER_GATEWAY_DISCORD_BOT_TOKEN)" || (echo "missing RELEASE_OWNER_GATEWAY_DISCORD_BOT_TOKEN" >&2; exit 2)
	@test -n "$(RELEASE_OWNER_GATEWAY_PYTHON)" || (echo "missing RELEASE_OWNER_GATEWAY_PYTHON" >&2; exit 2)
	@test -n "$(RELEASE_OWNER_GATEWAY_SIGNER_USER)" || (echo "missing RELEASE_OWNER_GATEWAY_SIGNER_USER" >&2; exit 2)
	@test -n "$(RELEASE_OWNER_GATEWAY_REQUESTER_USER)" || (echo "missing RELEASE_OWNER_GATEWAY_REQUESTER_USER" >&2; exit 2)
	@test -n "$(RELEASE_OWNER_GATEWAY_SUBMIT_GROUP)" || (echo "missing RELEASE_OWNER_GATEWAY_SUBMIT_GROUP" >&2; exit 2)
	@/bin/bash scripts/install-protected-release-owner-gateway.sh \
		--slug "$(RELEASE_OWNER_GATEWAY_SLUG)" \
		--signer-config "$(RELEASE_OWNER_GATEWAY_SIGNER_CONFIG)" \
		--discord-source-config "$(RELEASE_OWNER_GATEWAY_DISCORD_SOURCE_CONFIG)" \
		--signing-private-key "$(RELEASE_OWNER_GATEWAY_SIGNING_PRIVATE_KEY)" \
		--signing-public-key "$(RELEASE_OWNER_GATEWAY_SIGNING_PUBLIC_KEY)" \
		--discord-bot-token "$(RELEASE_OWNER_GATEWAY_DISCORD_BOT_TOKEN)" \
		--python "$(RELEASE_OWNER_GATEWAY_PYTHON)" \
		--signer-user "$(RELEASE_OWNER_GATEWAY_SIGNER_USER)" \
		--requester-user "$(RELEASE_OWNER_GATEWAY_REQUESTER_USER)" \
		--submit-group "$(RELEASE_OWNER_GATEWAY_SUBMIT_GROUP)"

uninstall-protected-release-owner-gateway:
	@test -n "$(RELEASE_OWNER_GATEWAY_SLUG)" || (echo "missing RELEASE_OWNER_GATEWAY_SLUG" >&2; exit 2)
	@/bin/bash scripts/uninstall-protected-release-owner-gateway.sh --slug "$(RELEASE_OWNER_GATEWAY_SLUG)"

privacy-scan:
	@$(PRODUCT_PYTHON) scripts/privacy-scan.py .
