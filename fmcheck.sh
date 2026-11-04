#!/bin/bash
#
# fmcheck.sh v1.5.0 - read-only FileMaker Server exposure & patch-level auditor
# NRG Software, LLC
#
# Per host it checks:
#   - Running FileMaker Server version (unauthenticated Data API productInfo)
#     vs the minimum patched release for its version line.
#   - Database INVENTORY exposed over the Data API (fmrest privilege).
#   - GUEST / anonymous access per file, over the Data API AND OData.
#   - WebDirect: whether an anonymous "Sign In as Guest" (POST ?api=login_list)
#     returns the hosted-file list, and the file names if it does.
#   - Which other web interfaces answer publicly (OData, XML CWP, Admin
#     Console on 443 and :16000).
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
# Changelog:
#   1.5.0 (2026-11-04) - WebDirect guest enumeration via POST ?api=login_list.
#   1.4.0 (2026-11-04) - Admin Console checked on 443 /admin-console/ AND :16000
#                        (blocking the port does not block the 443 path).
#   1.3.0 (2026-10-26) - OData: capture exposed entity sets + one-row probe to
#                        show whether records (not just schema) are readable;
#                        clearer "version withheld" vs "not reachable" message.
#   1.2.0 (2026-10-26) - Interactive mode: prompt for one host at a time.
#   1.1.0 (2026-10-26) - Data API inventory + guest checks (Data API & OData).
#   1.0.0 (2026-10-26) - Version/patch-level check, interface exposure, TLS.
#
# Usage:
#   ./fmcheck.sh                     # interactive: prompts for one host at a time
#   ./fmcheck.sh hosts.txt           # one hostname per line in hosts.txt
#   ./fmcheck.sh host1 host2 ...      # hostnames as arguments
#   ./fmcheck.sh --help
#
# hosts.txt: one host per line; blank lines and #comments ignored.
# Hostname only, no scheme, e.g.   fms.redwallprints.com

VERSION="1.5.0"
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
    echo "  [INFO] Data API   : $N file(s) exposed over REST:"
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
  elif reachable "$OROOT"; then
    echo "  [INFO] OData      : service root reachable (HTTP $OROOT)"
  else
    echo "  [OK]   OData      : not reachable"
  fi

  # --- Other interfaces ---
  C_XML=$(code_get "https://$H/fmi/xml/fmresultset.xml?-dbnames")
  C_ADMIN443=$(code_get "https://$H/admin-console/")
  C_ADMIN16=$(code_get "https://$H:$ADMIN_PORT/admin-console/")

  # --- WebDirect: does an anonymous "Sign In as Guest" return the file list? ---
  # The guest button POSTs /fmi/webd?api=login_list; a result:"0" response
  # carries the home-page HTML enumerating the hosted WebDirect files. The
  # names appear in the thumbnail URLs as /docws/<Name>?fms-command=getthumb.
  WCODE=$(code_get "https://$H/fmi/webd/")
  WBODY=$(curl -sk --max-time "$TIMEOUT" -X POST "https://$H/fmi/webd?api=login_list" 2>/dev/null)
  if echo "$WBODY" | grep -q '"result"[[:space:]]*:[[:space:]]*"0"'; then
    WDBS=$(echo "$WBODY" | grep -oE '/docws/[^?"]+\?fms-command=getthumb' \
           | sed -E 's#/docws/([^?]+)\?.*#\1#' | sort -u | paste -sd ',' -)
    [ -z "$WDBS" ] && WDBS="(result:0 but no names parsed)"
    echo "  [WARN] WebDirect  : guest sign-in returns the file list WITHOUT creds: $WDBS"
  elif reachable "$WCODE"; then
    echo "  [OK]   WebDirect  : reachable (HTTP $WCODE) - guest list not returned"
  else
    echo "  [OK]   WebDirect  : not reachable"
  fi

  if reachable "$C_XML"; then
    echo "  [WARN] XML CWP    : reachable (HTTP $C_XML) - review & disable if unused (CVE-2026-86934)"
  else
    echo "  [OK]   XML CWP    : not reachable"
  fi

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

echo "FileMaker host audit  v$VERSION  -  $(date '+%Y-%m-%d %H:%M:%S')"
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
