#!/usr/bin/env bash
# Live tests on a Cloud Run service: build the test image on this machine,
# push it to Artifact Registry, create or update the service, run the suites
# on it and print its logs. Authenticates with a service account JSON key
# only; the one-time setup is in the README ("Live tests on Cloud Run").
#
#   usage: tests/cloud-run.sh up|deploy|test|logs|down|all
#
#   up      check the project, create the Artifact Registry repository
#   deploy  build the test image, push it, create or update the service
#   test    run tests/live.py and tests/smoke.py on the service
#   logs    print the service's log entries of the last LOGS_SINCE (default 1h)
#   down    delete the service and the repository with its images
#   all     up, deploy, test, logs (the service stays; it scales to zero)
#
# Environment, also read from .env at the repository root (the environment wins):
#   GCP_KEY_FILE    service account JSON key (required)
#   GCP_REGION      region of the repository and the service (required)
#   GCP_PROJECT     defaults to the key's project_id
#   GCP_RUNTIME_SA  the service's identity, default <key's account>-runtime@PROJECT.iam.gserviceaccount.com
#   DOCKER          engine that builds the image, as in the Makefile (podman, docker)
set -euo pipefail

cd "$(dirname "$0")/.."
SETTINGS="GCP_KEY_FILE|GCP_REGION|GCP_PROJECT|GCP_RUNTIME_SA|DOCKER|LOGS_SINCE"
if [ -f .env ]; then
	from_env=$(export -p | grep -E "^declare -x ($SETTINGS)=" || true)
	set -a
	# shellcheck source=/dev/null
	. ./.env
	set +a
	eval "$from_env"
fi
DOCKER=${DOCKER:-podman}
LOGS_SINCE=${LOGS_SINCE:-1h}

REPO=sbx-live
SERVICE=sbx-live
SUITES="live smoke"

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "  ok   $1"; }
bad() { fail=$((fail + 1)); printf '  FAIL %s\n       %s\n' "$1" "$2"; }
die() { echo "cloud-run.sh: $*" >&2; exit 2; }
need() { for t; do command -v "$t" >/dev/null || die "$t is required"; done; }

# exists DESCRIBE-ARGS...: whether `gcloud DESCRIBE-ARGS` finds the resource.
# Any error other than "not found" (permissions, API disabled) stops the script.
exists() {
	local err
	if err=$(gcloud "$@" --format='value(name)' 2>&1 >/dev/null); then
		return 0
	fi
	case $err in
	*NOT_FOUND* | *"Cannot find"* | *"not found"*) return 1 ;;
	esac
	die "gcloud $*: $err"
}

# Activate the key in a throwaway gcloud configuration: the user's own gcloud
# login and configuration are never read or changed.
auth() {
	need gcloud jq
	[ -n "${GCP_KEY_FILE:-}" ] || die "set GCP_KEY_FILE to the service account JSON key (README: Live tests on Cloud Run)"
	[ -n "${GCP_REGION:-}" ] || die "set GCP_REGION, e.g. europe-west1"
	[ -r "$GCP_KEY_FILE" ] || die "GCP_KEY_FILE $GCP_KEY_FILE is not readable"
	[ "$(jq -r '.type // empty' "$GCP_KEY_FILE" 2>/dev/null)" = service_account ] ||
		die "$GCP_KEY_FILE is not a service account JSON key"
	SA=$(jq -r '.client_email // empty' "$GCP_KEY_FILE")
	PROJECT=${GCP_PROJECT:-$(jq -r '.project_id // empty' "$GCP_KEY_FILE")}
	[ -n "$SA" ] && [ -n "$PROJECT" ] || die "$GCP_KEY_FILE has no client_email or project_id"
	RUNTIME_SA=${GCP_RUNTIME_SA:-${SA%%@*}-runtime@$PROJECT.iam.gserviceaccount.com}
	REGISTRY=$GCP_REGION-docker.pkg.dev
	IMAGE=$REGISTRY/$PROJECT/$REPO/sbx-test

	TMP=$(mktemp -d "${TMPDIR:-/tmp}/sbx-live.XXXXXX")
	trap 'rm -rf "$TMP"' EXIT
	export CLOUDSDK_CONFIG=$TMP/gcloud CLOUDSDK_CORE_DISABLE_PROMPTS=1
	export CLOUDSDK_CORE_PROJECT=$PROJECT CLOUDSDK_RUN_REGION=$GCP_REGION CLOUDSDK_ARTIFACTS_LOCATION=$GCP_REGION
	local err
	err=$(gcloud auth activate-service-account --key-file="$GCP_KEY_FILE" 2>&1) ||
		die "cannot activate $GCP_KEY_FILE: ${err%%$'\n'*}"
	echo "== project $PROJECT, region $GCP_REGION, as $SA"
}

cmd_up() {
	echo "== up"
	exists iam service-accounts describe "$RUNTIME_SA" ||
		die "service account $RUNTIME_SA does not exist (README, one-time setup)"
	if exists artifacts repositories describe "$REPO"; then
		echo "  repository $REPO exists"
	else
		gcloud artifacts repositories create "$REPO" --repository-format=docker \
			--description="sbx live tests (tests/cloud-run.sh)"
	fi
}

# push IMAGE: log in with a short-lived access token (not the key) into an
# auth file under $TMP, so nothing is written to the engine's configuration.
push() (
	case $("$DOCKER" --version 2>/dev/null) in
	*podman*) export REGISTRY_AUTH_FILE=$TMP/auth.json ;;
	*)
		# A fresh DOCKER_CONFIG has no contexts: keep using the current daemon.
		if [ -z "${DOCKER_HOST:-}" ]; then
			DOCKER_HOST=$("$DOCKER" context inspect --format '{{.Endpoints.docker.Host}}')
			export DOCKER_HOST
		fi
		export DOCKER_CONFIG=$TMP/docker
		;;
	esac
	gcloud auth print-access-token | "$DOCKER" login -u oauth2accesstoken --password-stdin "$REGISTRY"
	"$DOCKER" push "$1"
)

cmd_deploy() {
	need git make "$DOCKER"
	exists artifacts repositories describe "$REPO" || die "repository $REPO does not exist: run tests/cloud-run.sh up"
	local version base digest
	version=$(git rev-parse --short=12 HEAD)
	[ -z "$(git status --porcelain)" ] || version=$version-dirty
	# Cloud Run runs linux/amd64 only. podman resolves a FROM tag to whatever
	# architecture is stored locally under that tag (arm64 on an arm64 Mac), so
	# the base image is named by its amd64 digest.
	base=$(make -s --no-print-directory print-TEST_BASE_IMAGE)
	digest=$("$DOCKER" manifest inspect "$base" |
		jq -r '[.manifests[]? | select(.platform.os == "linux" and .platform.architecture == "amd64")][0].digest // empty')
	[ -n "$digest" ] || die "$base has no linux/amd64 image"
	echo "== build $IMAGE:$version (linux/amd64, on ${base%:*}@$digest)"
	# The Makefile names the test image $(IMAGE)-test.
	make test-image DOCKER="$DOCKER" PLATFORM=linux/amd64 TEST_BASE_IMAGE="${base%:*}@$digest" \
		REGISTRY="$REGISTRY" IMAGE_NAME="$PROJECT/$REPO/sbx" VERSION="$version"
	echo "== push"
	push "$IMAGE:$version"
	digest=$(gcloud artifacts docker images describe "$IMAGE:$version" --format='value(image_summary.digest)')
	[ -n "$digest" ] || die "Artifact Registry has no digest for $IMAGE:$version"
	echo "== deploy $SERVICE ($IMAGE@$digest)"
	# The suites run as root inside one gen2 instance, one request at a time.
	# sbx-deployed changes on every run, so each deploy creates a new revision
	# and the suites start on a fresh instance (sbx rewrites /etc/resolv.conf,
	# and a reused instance would keep that from the previous run).
	cat >"$TMP/service.yaml" <<EOF
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: $SERVICE
spec:
  template:
    metadata:
      labels:
        sbx-version: $version
        sbx-deployed: "$(date -u +%Y%m%dt%H%M%Sz)"
      annotations:
        run.googleapis.com/execution-environment: gen2
        autoscaling.knative.dev/maxScale: "1"
    spec:
      serviceAccountName: $RUNTIME_SA
      containerConcurrency: 1
      timeoutSeconds: 3600
      containers:
        - image: $IMAGE@$digest
          command: [python3]
          args: [/opt/sbx/tests/live_server.py]
          env:
            - {name: SBX, value: /usr/local/bin/sbx}
            - {name: TEST_VOLUME, value: /mnt/sbx-vol}
            - {name: TEST_REQUIRE_IPV6, value: "false"}
            - {name: TEST_REQUIRE_LANDLOCK, value: "false"}
          resources:
            limits: {cpu: "1", memory: 1Gi}
          volumeMounts:
            - {name: test-volume, mountPath: /mnt/sbx-vol}
      volumes:
        - name: test-volume
          emptyDir: {medium: Memory, sizeLimit: 64Mi}
EOF
	gcloud run services replace "$TMP/service.yaml"
}

cmd_test() {
	need curl
	exists run services describe "$SERVICE" || die "service $SERVICE does not exist: run tests/cloud-run.sh deploy"
	local url token suite rc last results=""
	url=$(gcloud run services describe "$SERVICE" --format='value(status.url)')
	token=$(gcloud auth print-identity-token --audiences="$url")
	# The token goes to curl in a file, not on its command line.
	printf 'Authorization: Bearer %s\n' "$token" >"$TMP/auth-header"
	for suite in $SUITES; do
		echo "== suite $suite ($url/suite/$suite)"
		rc=0
		curl -sS -N --fail-with-body --max-time 3600 -H @"$TMP/auth-header" "$url/suite/$suite" |
			tee "$TMP/$suite.out" || rc=$?
		last=$(tail -n 1 "$TMP/$suite.out")
		results="$results$suite|$rc|$last"$'\n'
	done
	echo "== results"
	while IFS='|' read -r suite rc last; do
		[ -n "$suite" ] || continue
		if [ "$rc" = 0 ] && [ "$last" = "== exit 0" ]; then
			ok "$suite"
		else
			bad "$suite" "curl exit $rc, last line: $last"
		fi
	done <<<"$results"
}

logs_filter() {
	echo "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"$SERVICE\"" \
		"AND NOT logName:\"cloudaudit.googleapis.com\"${1:+ AND timestamp>=\"$1\"}"
}

# wait_for_logs SINCE: Cloud Logging lags; wait until it has the end of each suite.
wait_for_logs() {
	local filter suite n want=0 tries=0
	filter="$(logs_filter "$1") AND textPayload:\"== exit\""
	for suite in $SUITES; do want=$((want + 1)); done
	while [ "$tries" -lt 18 ]; do
		n=$(gcloud logging read "$filter" --freshness=1d --format='value(timestamp)' | wc -l)
		[ $((n)) -lt "$want" ] || return 0
		sleep 5
		tries=$((tries + 1))
	done
	echo "  (Cloud Logging has not caught up; run tests/cloud-run.sh logs later)"
}

# cmd_logs [SINCE]: entries since the RFC 3339 time SINCE, or of the last LOGS_SINCE.
cmd_logs() {
	local freshness=$LOGS_SINCE
	[ -z "${1:-}" ] || freshness=1d
	echo "== logs of $SERVICE (${1:+since }${1:-last $LOGS_SINCE})"
	gcloud logging read "$(logs_filter "${1:-}")" --freshness="$freshness" --order=asc \
		--format='value(timestamp,severity,textPayload,httpRequest.requestMethod,httpRequest.requestUrl,httpRequest.status)'
}

cmd_down() {
	echo "== down"
	if exists run services describe "$SERVICE"; then
		gcloud run services delete "$SERVICE" --quiet
	else
		echo "  no service $SERVICE"
	fi
	if exists artifacts repositories describe "$REPO"; then
		gcloud artifacts repositories delete "$REPO" --quiet
	else
		echo "  no repository $REPO"
	fi
}

cmd_all() {
	local since
	since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	cmd_up
	cmd_deploy
	cmd_test
	wait_for_logs "$since"
	cmd_logs "$since"
	echo "== $pass passed, $fail failed"
}

case ${1:-} in
up | deploy | test | logs | down | all) ;;
*) die "usage: tests/cloud-run.sh up|deploy|test|logs|down|all" ;;
esac
auth
"cmd_$1"
[ "$fail" = 0 ]
