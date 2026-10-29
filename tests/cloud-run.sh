#!/usr/bin/env bash
# Live tests on Cloud Run: build the test image on this machine, push it to
# Artifact Registry, create or update a service and two jobs, run the suites
# on them and print their logs. Authenticates with a service account JSON key
# only; the one-time setup is in the README ("Live tests on Cloud Run").
#
#   usage: tests/cloud-run.sh up|deploy|test|logs|down|all
#
#   up      check the project, create the Artifact Registry repository
#   deploy  build the test image, push it, create or update the targets
#   test    run the tests on each target:
#             service  tests/live.py and tests/smoke.py through tests/live_server.py
#             job      job sbx-live-suites: tests/live.py and tests/smoke.py as the task;
#                      job sbx-live-pid1: sbx as PID 1 running tests/live_net.py, and a
#                      run that must fail with sbx's timeout
#   logs    print the targets' log entries of the last LOGS_SINCE (default 1h)
#   down    delete the service, the jobs and the repository with its images
#   all     up, deploy, test, logs (nothing is deleted; the service scales to zero)
#
# Environment, also read from .env at the repository root (the environment wins):
#   GCP_KEY_FILE    service account JSON key (required)
#   GCP_REGION      region of the repository, the service and the jobs (required)
#   GCP_PROJECT     defaults to the key's project_id
#   GCP_RUNTIME_SA  the targets' identity, default <key's account>-runtime@PROJECT.iam.gserviceaccount.com
#   DOCKER          engine that builds the image, as in the Makefile (podman, docker)
#   TARGETS         what deploy, test and logs work on: "service job" (default), "service" or "job"
set -euo pipefail

cd "$(dirname "$0")/.."
SETTINGS="GCP_KEY_FILE|GCP_REGION|GCP_PROJECT|GCP_RUNTIME_SA|DOCKER|LOGS_SINCE|TARGETS"
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
TARGETS=${TARGETS:-service job}

REPO=sbx-live
SERVICE=sbx-live
SUITES_JOB=sbx-live-suites
PID1_JOB=sbx-live-pid1
SUITES="live smoke"

pass=0
fail=0
results=""
ok() { pass=$((pass + 1)); echo "  ok   $1"; }
bad() { fail=$((fail + 1)); printf '  FAIL %s\n       %s\n' "$1" "$2"; }
# result NAME [DETAIL]: record a test for the summary; no DETAIL means it passed.
result() { results="$results$1|${2:-}"$'\n'; }
die() { echo "cloud-run.sh: $*" >&2; exit 2; }
need() { for t; do command -v "$t" >/dev/null || die "$t is required"; done; }
has_target() { case " $TARGETS " in *" $1 "*) return 0 ;; esac; return 1; }

for t in $TARGETS; do
	case $t in
	service | job) ;;
	*) die "TARGETS: unknown target $t (use service, job or both)" ;;
	esac
done
[ -n "${TARGETS// /}" ] || die "TARGETS is empty"

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
	echo "== project $PROJECT, region $GCP_REGION, as $SA, targets: $TARGETS"
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
	local version base digest t
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
	for t in $TARGETS; do
		"deploy_$t" "$IMAGE@$digest" "$version"
	done
}

# deploy_service IMAGE VERSION
deploy_service() {
	echo "== deploy service $SERVICE ($1)"
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
        sbx-version: $2
        sbx-deployed: "$(date -u +%Y%m%dt%H%M%Sz)"
      annotations:
        run.googleapis.com/execution-environment: gen2
        autoscaling.knative.dev/maxScale: "1"
    spec:
      serviceAccountName: $RUNTIME_SA
      containerConcurrency: 1
      timeoutSeconds: 3600
      containers:
        - image: $1
          command: [python3]
          args: [/opt/sbx/tests/live_server.py]
          env:
            - {name: SBX, value: /usr/local/bin/sbx}
            - {name: TEST_VOLUME, value: /mnt/sbx-vol}
            - {name: TEST_REQUIRE_IPV6, value: "true"}
            - {name: TEST_REQUIRE_LANDLOCK, value: "false"}
            - {name: TEST_REQUIRE_CGROUP, value: "false"}
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

# deploy_job IMAGE VERSION
deploy_job() {
	local rules
	# The rules that tests/live_net.py's cases assume.
	rules=$(sed -n 's/^RULES = "\(.*\)"$/\1/p' tests/live_net.py)
	[ -n "$rules" ] || die "cannot read RULES from tests/live_net.py"
	echo "== deploy job $SUITES_JOB ($1)"
	# Each execution runs on a fresh gen2 instance, so nothing is left over
	# from the previous one. Executions choose the suite with --args.
	cat >"$TMP/$SUITES_JOB.yaml" <<EOF
apiVersion: run.googleapis.com/v1
kind: Job
metadata:
  name: $SUITES_JOB
  labels:
    sbx-version: $2
spec:
  template:
    metadata:
      annotations:
        run.googleapis.com/execution-environment: gen2
    spec:
      taskCount: 1
      parallelism: 1
      template:
        spec:
          serviceAccountName: $RUNTIME_SA
          maxRetries: 0
          timeoutSeconds: 3600
          containers:
            - image: $1
              command: [python3]
              args: ["-u", /opt/sbx/tests/live.py]
              env:
                - {name: SBX, value: /usr/local/bin/sbx}
                - {name: TEST_VOLUME, value: /mnt/sbx-vol}
                - {name: TEST_REQUIRE_IPV6, value: "true"}
                - {name: TEST_REQUIRE_LANDLOCK, value: "false"}
                - {name: TEST_REQUIRE_CGROUP, value: "false"}
              resources:
                limits: {cpu: "1", memory: 1Gi}
              volumeMounts:
                - {name: test-volume, mountPath: /mnt/sbx-vol}
          volumes:
            - name: test-volume
              emptyDir: {medium: Memory, sizeLimit: 64Mi}
EOF
	gcloud run jobs replace "$TMP/$SUITES_JOB.yaml"
	echo "== deploy job $PID1_JOB ($1)"
	# The README's job: the image's entrypoint (sbx run) is PID 1, configured
	# through SBX_* variables, with an in-memory volume as the working directory.
	cat >"$TMP/$PID1_JOB.yaml" <<EOF
apiVersion: run.googleapis.com/v1
kind: Job
metadata:
  name: $PID1_JOB
  labels:
    sbx-version: $2
spec:
  template:
    metadata:
      annotations:
        run.googleapis.com/execution-environment: gen2
    spec:
      taskCount: 1
      parallelism: 1
      template:
        spec:
          serviceAccountName: $RUNTIME_SA
          maxRetries: 0
          timeoutSeconds: 600
          containers:
            - image: $1
              args: ["--", python3, /opt/sbx/tests/live_net.py, job]
              env:
                - {name: SBX_POLICY_FILE, value: /etc/sbx/no-landlock.example.toml}
                - {name: SBX_EGRESS, value: "$rules"}
              resources:
                limits: {cpu: "1", memory: 1Gi}
              volumeMounts:
                - {name: work, mountPath: /workspace}
          volumes:
            - name: work
              emptyDir: {medium: Memory, sizeLimit: 64Mi}
EOF
	gcloud run jobs replace "$TMP/$PID1_JOB.yaml"
}

cmd_test() {
	local t name detail
	for t in $TARGETS; do
		"test_$t"
	done
	echo "== results"
	while IFS='|' read -r name detail; do
		[ -n "$name" ] || continue
		if [ -z "$detail" ]; then
			ok "$name"
		else
			bad "$name" "$detail"
		fi
	done <<<"$results"
}

test_service() {
	need curl
	exists run services describe "$SERVICE" || die "service $SERVICE does not exist: run tests/cloud-run.sh deploy"
	local url token suite rc last
	url=$(gcloud run services describe "$SERVICE" --format='value(status.url)')
	token=$(gcloud auth print-identity-token --audiences="$url")
	# The token goes to curl in a file, not on its command line.
	printf 'Authorization: Bearer %s\n' "$token" >"$TMP/auth-header"
	for suite in $SUITES; do
		echo "== service $SERVICE: suite $suite ($url/suite/$suite)"
		rc=0
		curl -sS -N --fail-with-body --max-time 3600 -H @"$TMP/auth-header" "$url/suite/$suite" |
			tee "$TMP/$suite.out" || rc=$?
		last=$(tail -n 1 "$TMP/$suite.out")
		if [ "$rc" = 0 ] && [ "$last" = "== exit 0" ]; then
			result "$suite"
		else
			result "$suite" "curl exit $rc, last line: $last"
		fi
	done
}

test_job() {
	local job
	for job in "$SUITES_JOB" "$PID1_JOB"; do
		exists run jobs describe "$job" || die "job $job does not exist: run tests/cloud-run.sh deploy"
	done
	# The suites print "== N passed, M failed" when they finish.
	execute "$SUITES_JOB" "" " passed, "
	check_execution "job:live" succeeded "== [0-9]+ passed, 0 failed"
	execute "$SUITES_JOB" "-u,/opt/sbx/tests/smoke.py" " passed, "
	check_execution "job:smoke" succeeded "== [0-9]+ passed, 0 failed"
	execute "$PID1_JOB" "" " passed, "
	check_execution "job:pid1 egress" succeeded "landlock: off" "== [0-9]+ passed, 0 failed"
	# A run with other arguments, as the README's per-execution example: sbx's
	# exit code 124 has to fail the task.
	execute "$PID1_JOB" "--timeout=2,--,/bin/sleep,30" "timeout after 2s"
	check_execution "job:pid1 timeout fails the task" failed "timeout after 2s"
}

# execute JOB ARGS MARKER: run one execution of JOB, with ARGS (gcloud's
# comma-separated --args) instead of the job's arguments unless empty, and wait
# until it has finished and its log line containing MARKER has reached Cloud
# Logging. Prints the log and sets EXECUTION (its name), OUTCOME (succeeded or
# failed) and LOG (a file with its log).
execute() {
	local job=$1 args=$2 marker=$3 state finished succeeded tries=0
	# --async, so that a failing execution still prints its name.
	EXECUTION=$(gcloud run jobs execute "$job" --async ${args:+"--args=$args"} --format='value(metadata.name)')
	[ -n "$EXECUTION" ] || die "gcloud run jobs execute $job did not name the execution"
	echo "== job $job: execution $EXECUTION${args:+ (args $args)}"
	while :; do
		state=$(gcloud run jobs executions describe "$EXECUTION" \
			--format='value[separator="|"](status.completionTime,status.succeededCount)')
		IFS='|' read -r finished succeeded <<<"$state"
		[ -z "$finished" ] || break
		tries=$((tries + 1))
		[ "$tries" -lt 400 ] || die "execution $EXECUTION has not finished after 4000s"
		sleep 10
	done
	OUTCOME=failed
	[ "${succeeded:-0}" != 1 ] || OUTCOME=succeeded
	local filter
	filter="$(logs_filter job) AND labels.\"run.googleapis.com/execution_name\"=\"$EXECUTION\""
	wait_for_logs "$filter AND textPayload:\"$marker\"" 1
	LOG=$TMP/$EXECUTION.log
	gcloud logging read "$filter" --freshness=1d --order=asc --format='value(timestamp,severity,textPayload)' |
		tee "$LOG"
	echo "== execution $EXECUTION $OUTCOME"
}

# check_execution NAME WANT PATTERN...: record whether the last execution
# ended WANT (succeeded or failed) and its log matches every extended regex PATTERN.
check_execution() {
	local name=$1 want=$2 p
	shift 2
	if [ "$OUTCOME" != "$want" ]; then
		result "$name" "execution $EXECUTION $OUTCOME, expected it to have $want"
		return
	fi
	for p; do
		if ! grep -Eq -- "$p" "$LOG"; then
			result "$name" "execution $EXECUTION: no log line matches /$p/"
			return
		fi
	done
	result "$name"
}

# logs_filter TARGET [SINCE]: the target's log entries, since the RFC 3339 time SINCE.
logs_filter() {
	local f
	case $1 in
	service) f="resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"$SERVICE\"" ;;
	job) f="resource.type=\"cloud_run_job\" AND (resource.labels.job_name=\"$SUITES_JOB\" OR resource.labels.job_name=\"$PID1_JOB\")" ;;
	esac
	echo "$f AND NOT logName:\"cloudaudit.googleapis.com\"${2:+ AND timestamp>=\"$2\"}"
}

# wait_for_logs FILTER N: Cloud Logging lags; wait until it has N entries matching FILTER.
wait_for_logs() {
	local n tries=0
	while [ "$tries" -lt 18 ]; do
		n=$(gcloud logging read "$1" --freshness=1d --format='value(timestamp)' | wc -l)
		[ $((n)) -lt "$2" ] || return 0
		sleep 5
		tries=$((tries + 1))
	done
	echo "  (Cloud Logging has not caught up; run tests/cloud-run.sh logs later)"
}

# cmd_logs [SINCE [TARGETS]]: entries since the RFC 3339 time SINCE, or of the
# last LOGS_SINCE, of TARGETS (default: all of $TARGETS).
cmd_logs() {
	local freshness=$LOGS_SINCE t
	[ -z "${1:-}" ] || freshness=1d
	for t in ${2:-$TARGETS}; do
		echo "== logs of the $t (${1:+since }${1:-last $LOGS_SINCE})"
		gcloud logging read "$(logs_filter "$t" "${1:-}")" --freshness="$freshness" --order=asc \
			--format='value(timestamp,severity,textPayload,httpRequest.requestMethod,httpRequest.requestUrl,httpRequest.status)'
	done
}

cmd_down() {
	local job
	echo "== down"
	if exists run services describe "$SERVICE"; then
		gcloud run services delete "$SERVICE" --quiet
	else
		echo "  no service $SERVICE"
	fi
	# Deleting a job deletes its executions.
	for job in "$SUITES_JOB" "$PID1_JOB"; do
		if exists run jobs describe "$job"; then
			gcloud run jobs delete "$job" --quiet
		else
			echo "  no job $job"
		fi
	done
	if exists artifacts repositories describe "$REPO"; then
		gcloud artifacts repositories delete "$REPO" --quiet
	else
		echo "  no repository $REPO"
	fi
}

cmd_all() {
	local since suite want=0
	since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	cmd_up
	cmd_deploy
	cmd_test
	# The jobs' logs were printed by the test step, execution by execution.
	if has_target service; then
		for suite in $SUITES; do want=$((want + 1)); done
		wait_for_logs "$(logs_filter service "$since") AND textPayload:\"== exit\"" "$want"
		cmd_logs "$since" service
	fi
	echo "== $pass passed, $fail failed"
}

case ${1:-} in
up | deploy | test | logs | down | all) ;;
*) die "usage: tests/cloud-run.sh up|deploy|test|logs|down|all" ;;
esac
auth
"cmd_$1"
[ "$fail" = 0 ]
