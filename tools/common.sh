# shellcheck shell=sh
# shellcheck disable=SC2034  # DC wird von den aufrufenden Skripten genutzt
# Gemeinsame Hilfen für die Hivornet-Skripte (wird per "." eingebunden).

die() { printf 'FEHLER: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

find_compose() {
  command -v docker >/dev/null 2>&1 || die "Docker ist nicht installiert (Synology: Paket 'Container Manager')."
  if docker compose version >/dev/null 2>&1; then
    DC="docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
  else
    die "Docker Compose fehlt."
  fi
  docker info >/dev/null 2>&1 || die "Kein Zugriff auf Docker. Mit sudo ausführen."
}

# env_get NAME: liest einen Wert aus .env, ohne die Datei als Shell-Skript auszuführen.
env_get() {
  [ -f .env ] || return 0
  grep -E "^$1=" .env | tail -n 1 | cut -d= -f2-
}

# env_set NAME WERT: setzt oder ergänzt einen Wert in .env (portabel, ohne sed -i).
env_set() {
  tmp=$(mktemp .env.XXXXXX)
  if grep -qE "^$1=" .env; then
    awk -v k="$1" -v v="$2" 'BEGIN{FS=OFS="="} $1==k {print k "=" v; next} {print}' .env >"$tmp"
  else
    cat .env >"$tmp"
    printf '%s=%s\n' "$1" "$2" >>"$tmp"
  fi
  chmod 600 "$tmp"
  mv "$tmp" .env
}

lan_ip() {
  ip=""
  if command -v ip >/dev/null 2>&1; then
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
  fi
  [ -n "$ip" ] || ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  printf '%s' "$ip"
}

rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1"; }
