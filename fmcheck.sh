#!/bin/bash
#
# fmcheck.sh - read-only FileMaker Server exposure & patch-level auditor
#
# Per host it checks:
#   - Running FileMaker Server version (unauthenticated Data API productInfo)
#     vs the minimum patched release for its version line.
#   - Database INVENTORY exposed over the Data API (fmrest privilege).
#     NOTE: the "filter databases" Admin Console setting does NOT reliably
#     hide this list - the check calls the endpoint and judges by the reply.
#   - WebDirect launch center (/fmi/webd): must show a sign-in page, not a
#     list of hosted file names. Fix is the server-level "Filter Databases in
#     Client Applications" setting - there is no WebDirect-specific setting.
#   - GUEST / anonymous access per file, over the Data API AND OData.
#   - XML CWP -dbnames in both grammars (fmresultset.xml, FMPXMLRESULT.xml):
#     flags any file names returned without login.
#   - Which FileMaker web interfaces answer publicly (OData, XML CWP,
#     WebDirect, Admin Console :16000).
#   - TLS certificate expiry.
#
# DEFENSIVE ONLY, on hosts YOU own: every request hits a metadata/version
# endpoint, attempts an anonymous login that is immediately logged out, or -
# ONLY when an OData endpoint already answered WITHOUT creds - reads at most
# one record to confirm the exposure (field values are never printed).
# Nothing is written, no credentials are guessed, no exploit payloads sent.
#
# Advisory context (versions this flags against):
#   26.0.3  fixes CVE-2026-86926 / -86930 / -86934 (Sep 2026 batch)
#           - 86934: XML WPE auth bypass via X-FMI-PE-ExtendedPrivilege header
#           - 86930: WebDirect thumbnail out-of-bounds read
#           - 86926: crafted .fmp12 heap overflow -> possible RCE
#   26.0.1  fixes CVE-2026-43752 (authed admin file-upload RCE)
#   22.0.4  fixes CVE-2025-46295 (critical text-substitution RCE, CVSS 9.8)
#   21.1.7  fixes CVE-2025-46295 on the 21.x line
#   20.3.2  fixes CVE-2024-27794 (WebDirect login reflected XSS)
#   NOTE: the Sep-2026 fixes are only *confirmed* in 26.0.3. On 22.x/21.x/20.x,
#   patch to the line minimum below AND confirm backport status with Claris.
#
# Usage:
#   ./fmcheck.sh                     # interactive: prompts for one host at a time
#   ./fmcheck.sh hosts.txt           # one hostname per line in hosts.txt
#   ./fmcheck.sh host1 host2 ...      # hostnames as arguments
#   ./fmcheck.sh --help
#
# hosts.txt: one host per line; blank lines and #comments ignored.
# Hostname only, no scheme, e.g.   fms.example.com

TIMEOUT=10
ADMIN_PORT=16000
TMP="${TMPDIR:-/tmp}/fmcheck.$$"

cleanup() { rm -f "$TMP" "${TMP}.r"; }
trap cleanup EXIT

usage() {
  cat <<'EOF'
fmcheck.sh - read-only FileMaker Server exposure & patch-level auditor

Usage:
  ./fmcheck.sh                    interactive: prompts for one host at a time
  ./fmcheck.sh hosts.txt          one hostname per line in hosts.txt
  ./fmcheck.sh host1 host2 ...    hostnames as arguments
  ./fmcheck.sh --help

Checks per host: FMS version vs patched release, databases exposed over the
Data API, guest/anonymous access over Data API and OData, reachable web
interfaces, and TLS expiry. Read-only; runs only against hosts you own.
EOF
  exit 0
}

[ "$1" = "--help" ] || [ "$1" = "-h" ] && usage

# ver_ge A B -> 0 if A>=B else 1 (numeric dotted compare)
ver_ge() {
  awk -v a="$1" -v b="$2" 'BEGIN{
    n=split(a,A,"."); m=split(b,B,"."); k=(n>m)?n:m;
    for(i=1;i<=k;i++){ x=(i<=n)?A[i]+0:0; y=(i<=m)?B[i]+0:0;
      if(x>y){print 0;exit} if(x<y){print 1;exit} }
    print 0 }'
}

min_for_line() {
  case "$1" in
    26) echo "26.0.3" ;; 22) echo "22.0.4" ;;
    21) echo "21.1.7" ;; 20) echo "20.3.2" ;;
    *)  echo "" ;;
  esac
}

# urlencode spaces and a few common chars in a file name for use in a path
urlenc() { echo "$1" | sed 's/%/%25/g; s/ /%20/g; s/#/%23/g; s/?/%3F/g; s/&/%26/g'; }

# GET code only
code_get() { curl -sk -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" "$1" 2>/dev/null; }
reachable() { [ "$1" != "000" ] && [ -n "$1" ]; }
# admin_hit CODE -> true if an admin-console path responded as present
#                   (reachable, and not a 404 "path not found")
admin_hit() { [ -n "$1" ] && [ "$1" != "000" ] && [ "$1" != "404" ]; }

# audit_host HOST  -> run every check against one host
audit_host() {
  H="$1"
  echo ""
  echo "HOST: $H"
  echo "------------------------------------------------------------"

  # --- Version (unauthenticated Data API productInfo) ---
  PCODE=$(code_get "https://$H/fmi/data/vLatest/productInfo")
  PINFO=$(curl -sk --max-time "$TIMEOUT" "https://$H/fmi/data/vLatest/productInfo" 2>/dev/null)
  VER=$(echo "$PINFO" | grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 \
        | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
  if [ -z "$VER" ]; then
    if reachable "$PCODE"; then
      echo "  [INFO] Version    : endpoint responded (HTTP $PCODE) but no version field"
      echo "         -> server is withholding its version; verify patch level in the Admin Console"
    else
      echo "  [INFO] Version    : endpoint not reachable (Data API off, blocked, or not FMS)"
    fi
  else
    MAJOR=$(echo "$VER" | cut -d. -f1); MIN=$(min_for_line "$MAJOR")
    if [ -z "$MIN" ]; then
      echo "  [WARN] Version    : $VER  (unrecognized line $MAJOR.x - verify against advisories)"
    elif [ "$(ver_ge "$VER" "$MIN")" = "0" ]; then
      echo "  [OK]   Version    : $VER  (>= $MIN for the $MAJOR.x line)"
    else
      echo "  [WARN] Version    : $VER  OUTDATED - minimum patched on $MAJOR.x line is $MIN"
      [ "$MAJOR" = "26" ] && echo "         -> below 26.0.3: exposed to CVE-2026-86926/-86930/-86934"
      [ "$MAJOR" != "26" ] && echo "         -> on $MAJOR.x: patch to $MIN; confirm Sep-2026 CVEs with Claris"
    fi
  fi

  # --- Database inventory exposed over the Data API ---
  DBJSON=$(curl -sk --max-time "$TIMEOUT" "https://$H/fmi/data/vLatest/databases" 2>/dev/null)
  DBS=$(echo "$DBJSON" | grep -oE '"name"[[:space:]]*:[[:space:]]*"[^"]+"' \
        | sed -E 's/.*"name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
  if [ -z "$DBS" ]; then
    echo "  [OK]   Data API   : no files exposed over REST (or Data API off)"
  else
    N=$(echo "$DBS" | grep -c .)
    echo "  [WARN] Data API   : $N file name(s) listed WITHOUT login at /fmi/data/vLatest/databases:"
    echo "         -> attackers use this list to pick login targets; the filter-databases"
    echo "            setting does not hide it. Disable the FileMaker Data API if unused"
    echo "            (Admin Console > Connectors > FileMaker Data API); otherwise remove"
    echo "            fmrest from every privilege set that does not need it."
    OLDIFS="$IFS"; IFS='
'
    for DB in $DBS; do
      ENC=$(urlenc "$DB")
      # Guest test over Data API: anonymous session create (no credentials)
      SCODE=$(curl -sk -o "$TMP" -w '%{http_code}' --max-time "$TIMEOUT" \
              -X POST -H 'Content-Type: application/json' \
              "https://$H/fmi/data/vLatest/databases/$ENC/sessions" --data '{}' 2>/dev/null)
      if [ "$SCODE" = "200" ]; then
        GUEST_DAPI="GUEST ENABLED (anonymous REST login succeeded)"
        TOKEN=$(grep -oE '"token"[[:space:]]*:[[:space:]]*"[^"]+"' "$TMP" | head -1 \
                | sed -E 's/.*"([^"]+)".*/\1/')
        [ -n "$TOKEN" ] && curl -sk --max-time "$TIMEOUT" -X DELETE \
                "https://$H/fmi/data/vLatest/databases/$ENC/sessions/$TOKEN" >/dev/null 2>&1
      else
        GUEST_DAPI="guest off (HTTP $SCODE)"
      fi
      # Guest test over OData: anonymous read of the file's service document.
      # On a 200 (no creds) capture the exposed entity sets, then probe one
      # set for actual rows - one record only, field values never printed.
      OEXTRA=""
      OCODE=$(curl -sk -o "$TMP" -w '%{http_code}' --max-time "$TIMEOUT" \
              "https://$H/fmi/odata/v4/$ENC" 2>/dev/null)
      if [ "$OCODE" = "200" ]; then
        GUEST_ODATA="GUEST ENABLED (anonymous OData read)"
        SETS=$(grep -oE '"name"[[:space:]]*:[[:space:]]*"[^"]+"' "$TMP" \
               | sed -E 's/.*:[[:space:]]*"([^"]+)".*/\1/' | head -8 | paste -sd ',' -)
        [ -z "$SETS" ] && SETS="(none parsed)"
        FIRST=$(grep -oE '"name"[[:space:]]*:[[:space:]]*"[^"]+"' "$TMP" \
                | sed -E 's/.*:[[:space:]]*"([^"]+)".*/\1/' | head -1)
        REC="metadata only (no rows read)"
        if [ -n "$FIRST" ]; then
          RCODE=$(curl -sk -o "${TMP}.r" -w '%{http_code}' --max-time "$TIMEOUT" \
                  "https://$H/fmi/odata/v4/$ENC/$(urlenc "$FIRST")?\$top=1" 2>/dev/null)
          if [ "$RCODE" = "200" ] && grep -qE '"value"[[:space:]]*:[[:space:]]*\[[[:space:]]*\{' "${TMP}.r"; then
            REC="RECORDS READABLE WITHOUT CREDS"
          elif [ "$RCODE" != "200" ]; then
            REC="records not readable (HTTP $RCODE)"
          fi
          rm -f "${TMP}.r"
        fi
        OEXTRA="yes"
      else
        GUEST_ODATA="guest off (HTTP $OCODE)"
      fi
      # Flag the line if either path allowed anonymous access
      case "$GUEST_DAPI$GUEST_ODATA" in
        *GUEST\ ENABLED*) TAG="  [WARN]" ;;
        *)                TAG="  [OK]  " ;;
      esac
      echo "$TAG   - $DB"
      echo "             Data API guest: $GUEST_DAPI"
      echo "             OData guest   : $GUEST_ODATA"
      if [ "$OEXTRA" = "yes" ]; then
        echo "             OData exposes : $SETS"
        echo "             OData records : $REC"
      fi
    done
    IFS="$OLDIFS"
  fi

  # --- OData service root (server-level) ---
  # If the root ever returns 200 without creds it has handed back a catalog;
  # capture the names so the leak is shown, not just inferred.
  OROOT=$(curl -sk -o "$TMP" -w '%{http_code}' --max-time "$TIMEOUT" "https://$H/fmi/odata/v4" 2>/dev/null)
  if [ "$OROOT" = "200" ]; then
    CATS=$(grep -oE '"name"[[:space:]]*:[[:space:]]*"[^"]+"' "$TMP" \
           | sed -E 's/.*:[[:space:]]*"([^"]+)".*/\1/' | head -8 | paste -sd ',' -)
    echo "  [WARN] OData      : root returned a catalog WITHOUT creds (HTTP 200): ${CATS:-see body}"
    echo "         -> disable OData if unused (Admin Console > Connectors > OData), otherwise"
    echo "            remove fmodata from every privilege set that does not need it."
  elif reachable "$OROOT"; then
    echo "  [INFO] OData      : service root reachable (HTTP $OROOT)"
  else
    echo "  [OK]   OData      : not reachable"
  fi

  # --- Other interfaces ---
  C_WEBD=$(curl -skL -o "$TMP" -w '%{http_code}' --max-time "$TIMEOUT" "https://$H/fmi/webd/" 2>/dev/null)
  # Unfiltered launch center draws each hosted file with the iwp_db icon or a
  # getthumb thumbnail; the sign-in-first page has neither.
  WD_FILES=$(grep -oE 'iwp_db@[0-9]x\.png|fms-command=getthumb' "$TMP" 2>/dev/null | grep -c .)
  grep -q 'Client must provide account information' "$TMP" 2>/dev/null && WD_LOGIN=1 || WD_LOGIN=0
  C_ADMIN443=$(code_get "https://$H/admin-console/")
  C_ADMIN16=$(code_get "https://$H:$ADMIN_PORT/admin-console/")

  if ! reachable "$C_WEBD"; then
    echo "  [OK]   WebDirect  : not reachable"
  elif [ "$WD_FILES" -gt 0 ]; then
    echo "  [WARN] WebDirect  : /fmi/webd lists hosted files WITHOUT login (~$WD_FILES file icon(s))"
    echo "         -> fix: enable \"Filter Databases in Client Applications\" in the Admin Console"
    echo "            (a server setting, not a WebDirect setting); /fmi/webd then shows sign-in first"
  elif [ "$WD_LOGIN" = "1" ]; then
    echo "  [OK]   WebDirect  : /fmi/webd shows sign-in page, no file names (HTTP $C_WEBD)"
  else
    echo "  [INFO] WebDirect  : reachable (HTTP $C_WEBD) - page not recognised, check in a browser"
  fi

  # XML Custom Web Publishing: try -dbnames in BOTH grammars and read the reply.
  # fmresultset.xml returns names in <data>, FMPXMLRESULT.xml in <DATA>.
  XML_ANY=0
  for GRAM in fmresultset FMPXMLRESULT; do
    XURL="https://$H/fmi/xml/$GRAM.xml?-dbnames"
    XCODE=$(curl -sk -o "$TMP" -w '%{http_code}' --max-time "$TIMEOUT" "$XURL" 2>/dev/null)
    reachable "$XCODE" || continue
    XML_ANY=1
    XNAMES=$(grep -oiE '<data>[^<]*</data>' "$TMP" 2>/dev/null \
             | sed -E 's/<[^>]*>//g' | grep -v '^$' | paste -sd ',' -)
    if [ -n "$XNAMES" ]; then
      echo "  [WARN] XML CWP    : $GRAM.xml?-dbnames lists file names WITHOUT login (HTTP $XCODE): $XNAMES"
      echo "         -> disable XML Web Publishing if unused (Admin Console > Connectors > Web"
      echo "            Publishing), otherwise remove fmxml from every privilege set that does not need it."
    else
      echo "  [WARN] XML CWP    : $GRAM.xml reachable (HTTP $XCODE), no file names returned"
      echo "         -> review & disable if unused (CVE-2026-86934)"
    fi
  done
  [ "$XML_ANY" = "0" ] && echo "  [OK]   XML CWP    : not reachable (fmresultset.xml and FMPXMLRESULT.xml)"

  # Admin Console runs on 443 at /admin-console/ AND (historically) on :16000.
  # Blocking the port does NOT block the 443 path - check both. A 404 means
  # the path isn't present; 000 means no response.
  if admin_hit "$C_ADMIN443"; then
    echo "  [WARN] Admin Con. : reachable on 443 at /admin-console/ (HTTP $C_ADMIN443) - restrict to trusted IPs/VPN"
  else
    echo "  [OK]   Admin Con. : /admin-console/ on 443 not reachable"
  fi
  if admin_hit "$C_ADMIN16"; then
    echo "  [WARN] Admin Con. : port $ADMIN_PORT reachable (HTTP $C_ADMIN16) - restrict to trusted IPs/VPN"
  else
    echo "  [OK]   Admin Con. : port $ADMIN_PORT not reachable"
  fi

  # --- TLS certificate expiry ---
  ENDDATE=$(echo | openssl s_client -connect "$H:443" -servername "$H" 2>/dev/null \
            | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  if [ -z "$ENDDATE" ]; then
    echo "  [INFO] TLS cert   : could not read"
  elif echo | openssl s_client -connect "$H:443" -servername "$H" 2>/dev/null \
       | openssl x509 -noout -checkend 2592000 >/dev/null 2>&1; then
    echo "  [OK]   TLS cert   : valid, expires $ENDDATE"
  else
    echo "  [WARN] TLS cert   : expires within 30 days ($ENDDATE)"
  fi
}

footer() {
  echo ""
  echo "============================================================"
  echo "Done. [WARN] = review; [INFO] = reachable, confirm it's intended."
  echo "Admin-only items (admin password strength, account/privilege review)"
  echo "are not visible here - see the checklist."
}

echo "FileMaker host audit  -  $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"

# --- Mode selection ---
if [ $# -eq 0 ]; then
  # Interactive: prompt for one host at a time; blank line to quit.
  echo "Interactive mode. Enter a hostname to audit, or press Enter to quit."
  while true; do
    printf 'Hostname> '
    read -r H || break
    [ -z "$H" ] && break
    audit_host "$H"
  done
  footer
  exit 0
fi

if [ $# -eq 1 ] && [ -f "$1" ]; then
  # File of hosts
  HOSTS=$(grep -v '^[[:space:]]*#' "$1" | grep -v '^[[:space:]]*$' | awk '{print $1}')
else
  HOSTS="$*"
fi

for H in $HOSTS; do
  audit_host "$H"
done
footer
