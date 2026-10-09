#!/bin/sh
# Template security scan (docs/security.md M43). Runs as the sandbox user (uid 1000) inside a
# throwaway sandbox of the template, through the ordinary exec path, so it sees exactly what an
# agent would. Prints one JSON line per check: {"id","class","ok","detail"}.
#   boundary  what the tier's isolation promises; any failure grades the template F
#   hygiene   what the image carries (linPEAS-style); each failure lowers the grade
# A check that cannot run here says so in `detail` and counts as passed: the boundary it probes
# is enforced outside the sandbox either way. POSIX sh, no dependencies beyond coreutils.

out() { # id class ok detail
	d=$(printf '%s' "$4" | tr -d '"\\' | tr '\n\t' '  ' | cut -c1-240)
	printf '{"id":"%s","class":"%s","ok":%s,"detail":"%s"}\n' "$1" "$2" "$3" "$d"
}
have() { command -v "$1" >/dev/null 2>&1; }
status() { sed -n "s/^$1:[[:space:]]*//p" /proc/self/status; }

# One HTTP request that must NOT succeed; prints the status code (000 = no connection).
http_code() { # url noproxy(1|0)
	if have curl; then
		if [ "$2" = 1 ]; then curl --noproxy '*' -s -m 4 -o /dev/null -w '%{http_code}' "$1"
		else curl -s -m 4 -o /dev/null -w '%{http_code}' "$1"; fi
	elif have python3; then
		python3 - "$1" "$2" <<'PY' 2>/dev/null || echo 000
import sys, urllib.request
h = {} if sys.argv[2] == "1" else None
o = urllib.request.build_opener(urllib.request.ProxyHandler(h) if h is not None else urllib.request.ProxyHandler())
try: print(o.open(sys.argv[1], timeout=4).status)
except urllib.error.HTTPError as e: print(e.code)
except Exception: print("000")
PY
	else echo none; fi
}

# ---------------------------------------------------------------- boundary
v=$(status CapEff)
[ "$v" = 0000000000000000 ] && out caps boundary true "CapEff=$v" || out caps boundary false "CapEff=$v: the sandbox user holds capabilities"
v=$(status NoNewPrivs)
[ "$v" = 1 ] && out no_new_privs boundary true "NoNewPrivs=1" || out no_new_privs boundary false "NoNewPrivs=$v: setuid binaries can raise privileges"
v=$(status Seccomp)
[ "$v" = 2 ] && out seccomp boundary true "Seccomp=2 (filter)" || out seccomp boundary false "Seccomp=$v: no syscall filter"

m=$(mktemp -d 2>/dev/null || echo /tmp/sbx-probe-m)
if ! have mount; then out mount boundary true "not checked: no mount binary"
elif mount -t tmpfs none "$m" 2>/dev/null; then umount "$m" 2>/dev/null; out mount boundary false "mount(2) succeeded"
else out mount boundary true "mount(2) denied"; fi
rmdir "$m" 2>/dev/null
if ! have unshare; then out userns boundary true "not checked: no unshare binary"
elif unshare -U true 2>/dev/null; then out userns boundary false "unshare -U succeeded: a new user namespace is available"
else out userns boundary true "user namespaces denied"; fi

s=""
for p in /var/run/docker.sock /run/docker.sock /run/podman/podman.sock /run/containerd/containerd.sock /var/run/crio/crio.sock; do
	[ -S "$p" ] && s="$s $p"
done
[ -z "$s" ] && out runtime_socket boundary true "no container runtime socket" || out runtime_socket boundary false "reachable:$s"

c=$(http_code https://1.1.1.1/ 1)
case $c in none) out egress_direct boundary true "not checked: no curl or python3" ;;
	000) out egress_direct boundary true "direct connection bypassing the proxy failed" ;;
	*) out egress_direct boundary false "direct connection to 1.1.1.1 answered $c" ;; esac
# Direct only: through the proxy the address is refused by policy (proxy.rs, unit-tested), and
# asking would raise a metadata.probe alert on every scan.
c=$(http_code http://169.254.169.254/latest/meta-data/ 1)
case $c in none) out metadata boundary true "not checked: no curl or python3" ;;
	000) out metadata boundary true "metadata endpoint unreachable" ;;
	*) out metadata boundary false "metadata endpoint answered $c" ;; esac

if have getent; then r=$(getent hosts example.com 2>/dev/null)
elif have python3; then r=$(python3 -c 'import socket;print(socket.gethostbyname("example.com"))' 2>/dev/null)
else r=skip; fi
case $r in skip) out dns boundary true "not checked: no getent or python3" ;;
	"") out dns boundary true "no resolver: names resolve only through the proxy" ;;
	*) out dns boundary false "the sandbox resolves names itself: $r" ;; esac

KEYS='^([A-Z_]*API_KEY|ANTHROPIC[A-Z_]*|OPENAI[A-Z_]*|CLAUDE[A-Z_]*_TOKEN|GEMINI[A-Z_]*|MISTRAL[A-Z_]*|COHERE[A-Z_]*|GROQ[A-Z_]*|HF_TOKEN|HUGGING_FACE[A-Z_]*)=.'
v=$(env | grep -E "$KEYS" | cut -d= -f1 | tr '\n' ' ')
[ -z "$v" ] && out env_llm_keys boundary true "no model API keys in the environment" || out env_llm_keys boundary false "model API keys in the environment: $v"
if [ -r /proc/1/environ ]; then
	v=$(tr '\0' '\n' </proc/1/environ | grep -E "$KEYS|^SBX_AGENT_TOKEN=[^x]" | cut -d= -f1 | tr '\n' ' ')
	[ -z "$v" ] && out pid1_environ boundary true "/proc/1/environ holds no secret" || out pid1_environ boundary false "/proc/1/environ exposes: $v"
else out pid1_environ boundary true "/proc/1/environ unreadable"; fi

# ---------------------------------------------------------------- hygiene
# Set-id programs a Debian/Ubuntu/RHEL base ships. Under no_new_privs they cannot raise privileges;
# anything else was added by the template and is worth a look.
SETID=' su sudo mount umount passwd chsh chfn gpasswd newgrp unix_chkpwd chage expiry pam_extrausers_chkpwd wall write ssh-agent crontab dotlockfile fusermount fusermount3 ping ping6 pkexec newuidmap newgidmap utempter chrome-sandbox '
v=$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read -r f; do
	case "$SETID" in (*" ${f##*/} "*) ;; (*) printf ' %s' "$f" ;; esac
done)
[ -z "$v" ] && out setid_files hygiene true "only standard set-id programs" || out setid_files hygiene false "unexpected set-id programs:$v"

if have getcap; then v=$(getcap -r /usr /bin /sbin /opt 2>/dev/null | cut -d' ' -f1 | tr '\n' ' '); how=getcap
elif have python3; then how=python3; v=$(python3 - <<'PY' 2>/dev/null
import os
hits = []
for top in ("/usr", "/bin", "/sbin", "/opt"):
    for root, _, files in os.walk(top):
        for n in files:
            p = os.path.join(root, n)
            try:
                os.getxattr(p, "security.capability", follow_symlinks=False); hits.append(p)
            except OSError:
                pass
print(" ".join(hits))
PY
); else how=none; fi
case $how in none) out file_caps hygiene true "not checked: no getcap or python3" ;;
	*) [ -z "$v" ] && out file_caps hygiene true "no file capabilities" || out file_caps hygiene false "file capabilities on: $v" ;; esac

v=""
for d in $(printf '%s' "$PATH" | tr ':' ' '); do
	[ -d "$d" ] && [ -n "$(find -H "$d" -maxdepth 0 -perm -0002 2>/dev/null)" ] && v="$v $d"
	[ -d "$d" ] && [ -w "$d" ] && case "$v" in *"$d"*) ;; *) v="$v $d" ;; esac
done
[ -z "$v" ] && out path_writable hygiene true "no writable directory on PATH" || out path_writable hygiene false "writable PATH directories:$v"

v=""
for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ld.so.preload /usr/bin /usr/local/bin /etc; do
	[ -w "$f" ] && v="$v $f"
done
[ -z "$v" ] && out system_writable hygiene true "system files and directories are not writable" || out system_writable hygiene false "writable by the sandbox user:$v"

v=$(find /etc /opt /srv /home /root /usr/local/etc /var/lib -xdev -maxdepth 6 -type f -readable -size -1024k \
	\( -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '*.key' \
	-o -name '.env' -o -name '*.env' -o -name '.netrc' -o -name '.git-credentials' -o -name 'credentials' \
	-o -name '.pypirc' -o -name '.npmrc' -o -name 'config.json' \) 2>/dev/null |
	while read -r f; do
		# The guest agent's own decoys (canary.read): planted per sandbox, not baked in.
		grep -q 'sbx-canary-' "$f" 2>/dev/null && continue
		case $f in
		(*.env | */.netrc | */.git-credentials | */.pypirc) echo "$f" ;;
		(*/credentials) grep -qiE 'aws_secret_access_key|client_secret|token' "$f" 2>/dev/null && echo "$f" ;;
		(*/.npmrc) grep -q '_authToken' "$f" 2>/dev/null && echo "$f" ;;
		(*/config.json) case $f in (*/.docker/*) grep -q '"auth"' "$f" 2>/dev/null && echo "$f" ;; esac ;;
		(*) grep -qE 'BEGIN ([A-Z]+ )?PRIVATE KEY' "$f" 2>/dev/null && echo "$f" ;;
		esac
	done | tr '\n' ' ')
[ -z "$v" ] && out baked_secrets hygiene true "no readable keys or credential files in the image" || out baked_secrets hygiene false "readable secrets: $v"

v=$(grep -hsE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/* | head -3 | tr '\n' ';')
[ -z "$v" ] && out sudoers hygiene true "no readable passwordless sudo rule" || out sudoers hygiene false "passwordless sudo: $v"
exit 0
