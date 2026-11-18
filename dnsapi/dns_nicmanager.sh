#!/usr/bin/env sh
# nicmanager DNS-01 provider for acme.sh; record IDs are kept for cleanup.
# shellcheck disable=SC2034

dns_nicmanager_info='nicmanager AnycastDNS API
Site: nicmanager.com
Docs: github.com/acmesh-official/acme.sh/wiki/dnsapi2#dns_nicmanager
Options:
 NICMANAGER_USERNAME API username.
 NICMANAGER_PASSWORD API password.
 NICMANAGER_TOTP_SECRET Base32 TOTP secret. Optional.
 NICMANAGER_ZONE Explicit DNS zone. Optional.
 NICMANAGER_USE_ENV Use environment credentials without saving them. Optional.
Issues: github.com/acmesh-official/acme.sh/issues
Author: @rudnerbjoern
'

_nicmanager_totp() {
  _nm_secret=$(printf '%s' "$1" | LC_ALL=C tr '[:lower:]' '[:upper:]' | tr -d ' =')
  case "$_nm_secret" in ''|*[!A-Z2-7]*) return 1 ;; esac
  _nm_alphabet=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
  _nm_buffer=0 _nm_bits=0 _nm_key=
  while [ -n "$_nm_secret" ]; do
    _nm_char=${_nm_secret%"${_nm_secret#?}"}
    _nm_secret=${_nm_secret#?}
    _nm_before=${_nm_alphabet%%"$_nm_char"*}
    _nm_buffer=$(((_nm_buffer << 5) | ${#_nm_before}))
    _nm_bits=$((_nm_bits + 5))
    if [ "$_nm_bits" -ge 8 ]; then
      _nm_bits=$((_nm_bits - 8))
      _nm_key="$_nm_key$(printf '%02x' $(((_nm_buffer >> _nm_bits) & 255)))"
      _nm_buffer=$((_nm_buffer & ((1 << _nm_bits) - 1)))
    fi
  done
  [ -n "$_nm_key" ] || return 1
  _nm_counter=$(($(date +%s) / 30))
  # Convert the eight-byte big-endian counter to Base64 using only shell text.
  # Decoding it directly into OpenSSL avoids NUL bytes in shell variables.
  _nm_b64_alphabet=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
  _nm_ctr_b64=
  for _nm_shift in 58 52 46 40 34 28 22 16 10 4; do
    _nm_index=$(((_nm_counter >> _nm_shift) & 63))
    _nm_ctr_b64="$_nm_ctr_b64$(printf '%s' "$_nm_b64_alphabet" | cut -c "$((_nm_index + 1))")"
  done
  _nm_index=$(((_nm_counter & 15) << 2))
  _nm_ctr_b64="$_nm_ctr_b64$(printf '%s' "$_nm_b64_alphabet" | cut -c "$((_nm_index + 1))")="
  _nm_mac=$(printf '%s' "$_nm_ctr_b64" | _dbase64 | ${ACME_OPENSSL_BIN:-openssl} dgst -sha1 -mac HMAC -macopt "hexkey:$_nm_key" | sed 's/^.*= //') || return 1
  case "$_nm_mac" in *[!0-9a-fA-F]*|'') return 1 ;; esac
  [ "${#_nm_mac}" -eq 40 ] || return 1
  _nm_last=${_nm_mac#???????????????????????????????????????}
  _nm_offset=$((0x$_nm_last * 2 + 1))
  _nm_part=$(printf '%s' "$_nm_mac" | cut -c "$_nm_offset-$((_nm_offset + 7))")
  printf '%06d' $(((0x$_nm_part & 2147483647) % 1000000))
}

_nicmanager_setup() {
  if [ "${NICMANAGER_USE_ENV:-}" != 1 ]; then
    NICMANAGER_USERNAME=${NICMANAGER_USERNAME:-$(_readaccountconf_mutable NICMANAGER_USERNAME)}
    NICMANAGER_PASSWORD=${NICMANAGER_PASSWORD:-$(_readaccountconf_mutable NICMANAGER_PASSWORD)}
    NICMANAGER_TOTP_SECRET=${NICMANAGER_TOTP_SECRET:-$(_readaccountconf_mutable NICMANAGER_TOTP_SECRET)}
    NICMANAGER_ZONE=${NICMANAGER_ZONE:-$(_readaccountconf_mutable NICMANAGER_ZONE)}
  fi
  if [ -z "$NICMANAGER_USERNAME" ] || [ -z "$NICMANAGER_PASSWORD" ]; then
    _err 'nicmanager username and password are required.'
    return 1
  fi
  if [ "${NICMANAGER_USE_ENV:-}" != 1 ]; then
    _saveaccountconf_mutable NICMANAGER_USERNAME "$NICMANAGER_USERNAME" 1
    _saveaccountconf_mutable NICMANAGER_PASSWORD "$NICMANAGER_PASSWORD" 1
    [ -z "$NICMANAGER_TOTP_SECRET" ] || _saveaccountconf_mutable NICMANAGER_TOTP_SECRET "$NICMANAGER_TOTP_SECRET" 1
    [ -z "$NICMANAGER_ZONE" ] || _saveaccountconf_mutable NICMANAGER_ZONE "$NICMANAGER_ZONE"
  fi
  _nm_credentials=$(printf '%s' "$NICMANAGER_USERNAME:$NICMANAGER_PASSWORD" | _base64)
  export _H1="Authorization: Basic $_nm_credentials"
  export _H2='Accept: application/json'
  if [ -n "$NICMANAGER_TOTP_SECRET" ]; then
    _nm_otp=$(_nicmanager_totp "$NICMANAGER_TOTP_SECRET") || { _err 'Invalid nicmanager TOTP secret or OpenSSL failure.'; return 1; }
    export _H3="X-Auth-Token: $_nm_otp"
  else
    _H3=
    export _H3
  fi
}

_nicmanager_state_path() {
  case "$1" in ''|*[!a-zA-Z0-9._-]*) return 1 ;; esac
  case "$2" in ''|*[!a-zA-Z0-9_-]*) return 1 ;; esac
  _nm_hash=$(printf '%s\n%s' "$1" "$2" | openssl dgst -sha256 | sed 's/^.*= //') || return 1
  case "$_nm_hash" in *[!0-9a-fA-F]*|'') return 1 ;; esac
  _nm_state_dir="$ACCOUNT_CONF_PATH.nicmanager-records"
  (umask 077; mkdir -p "$_nm_state_dir") || return 1
  _nm_state="$_nm_state_dir/$_nm_hash"
}

_nicmanager_request() {
  _nicmanager_setup || return 1
  _inithttp
  _nm_response=$(_post "$1" "https://api.nicmanager.com/v1/anycast/$2" '' "$3" 'application/json') || { _err 'nicmanager request failed; do not retry before checking connectivity.'; return 1; }
  _nm_status=$(sed -n 's/^HTTP\/[0-9.]* \([0-9][0-9][0-9]\).*/\1/p' "$HTTP_HEADER" | tail -n 1 | tr -d '\r')
  case "$_nm_status" in [0-9][0-9][0-9]) ;; *) _err 'nicmanager returned no HTTP status.'; return 1 ;; esac
}

dns_nicmanager_add() {
  _nm_domain=$1 _nm_value=$2
  _nicmanager_setup || return 1
  _nicmanager_state_path "$_nm_domain" "$_nm_value" || { _err 'Invalid challenge or state directory.'; return 1; }
  if ! (umask 077; mkdir "$_nm_state"); then
    _err 'A record for this challenge is already tracked; inspect it before retrying.'
    return 1
  fi
  _nm_zone=${NICMANAGER_ZONE:-${_nm_domain#_acme-challenge.}}
  case "$_nm_zone" in ''|*[!a-zA-Z0-9.-]*|.*|*.) rmdir "$_nm_state"; _err 'Invalid DNS zone.'; return 1 ;; esac
  while :; do
    _nm_payload=$(printf '{"name":"%s","type":"TXT","value":"%s","ttl":900}' "$_nm_domain" "$_nm_value")
    if ! _nicmanager_request "$_nm_payload" "$_nm_zone/records" POST; then
      _err "Record state retained at $_nm_state; the API result may be unknown."
      return 1
    fi
    case "$_nm_status" in
      2??)
        _nm_id=$(printf '%s' "$_nm_response" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
        case "$_nm_id" in ''|*[!0-9]*) _err "Record ID missing; inspect $_nm_state and the DNS provider."; return 1 ;; esac
        (umask 077; printf '%s\n%s\n' "$_nm_zone" "$_nm_id" >"$_nm_state/record") || { _err "Could not store record ID $_nm_id in $_nm_state."; return 1; }
        _info 'nicmanager challenge record created.'
        return 0 ;;
      403|404)
        if [ -n "$NICMANAGER_ZONE" ]; then break; fi
        _nm_next=${_nm_zone#*.}
        [ "$_nm_next" != "$_nm_zone" ] && [ "${_nm_next#*.}" != "$_nm_next" ] || break
        _nm_zone=$_nm_next ;;
      *) rmdir "$_nm_state"; _err "nicmanager returned HTTP $_nm_status; no automatic authentication retry."; return 1 ;;
    esac
  done
  rmdir "$_nm_state"
  _err "No accessible nicmanager zone found (HTTP $_nm_status)."
  return 1
}

dns_nicmanager_rm() {
  _nicmanager_state_path "$1" "$2" || return 1
  if [ ! -f "$_nm_state/record" ]; then
    _err "No tracked nicmanager record for this challenge: $_nm_state"
    return 1
  fi
  _nm_zone=$(sed -n '1p' "$_nm_state/record")
  _nm_id=$(sed -n '2p' "$_nm_state/record")
  case "$_nm_zone" in ''|*[!a-zA-Z0-9.-]*) _err 'Invalid stored zone.'; return 1 ;; esac
  case "$_nm_id" in ''|*[!0-9]*) _err 'Invalid stored record ID.'; return 1 ;; esac
  _nicmanager_request '' "$_nm_zone/records/$_nm_id" DELETE || return 1
  case "$_nm_status" in
    2??) rm -f "$_nm_state/record" && rmdir "$_nm_state" || return 1; _info 'nicmanager challenge record removed.' ;;
    *) _err "nicmanager deletion returned HTTP $_nm_status; record state retained at $_nm_state."; return 1 ;;
  esac
}
