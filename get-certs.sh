#!/bin/sh

set -eu

# ============================================================================
# HTTPS hosts used by the application
#
# Add every HTTPS host that the application may connect to.
#
# Port is optional. 443 is used by default.
# ============================================================================

HOSTS="
github.com
api.github.com
objects.githubusercontent.com
github-releases.githubusercontent.com
"

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"
TMP_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT INT TERM

# ============================================================================
# Requirements
# ============================================================================

command -v openssl >/dev/null 2>&1 || {
    echo "ERROR: openssl is not installed." >&2
    exit 1
}

mkdir -p "$CERTS_DIR"

# Remove old certificates.
rm -f "$CERTS_DIR"/*.der

# ============================================================================
# Find OpenSSL system certificate store
# ============================================================================

OPENSSL_DIR=$(
    openssl version -d |
    sed -n 's/^OPENSSLDIR: "\(.*\)"$/\1/p'
)

if [ -z "$OPENSSL_DIR" ]; then
    echo "ERROR: unable to determine OpenSSL OPENSSLDIR." >&2
    exit 1
fi

echo "OpenSSL directory: $OPENSSL_DIR"

#
# OpenSSL normally uses:
#
#   OPENSSLDIR/cert.pem
#   OPENSSLDIR/certs/
#
# On Debian/Ubuntu this is commonly backed by:
#
#   /etc/ssl/cert.pem
#   /etc/ssl/certs/
#
# The actual paths may also be overridden by environment variables.
#

if [ -n "${SSL_CERT_FILE:-}" ] && [ -f "$SSL_CERT_FILE" ]; then
    CA_FILE="$SSL_CERT_FILE"
else
    CA_FILE="$OPENSSL_DIR/cert.pem"

    if [ ! -f "$CA_FILE" ]; then
        if [ -f "/etc/ssl/certs/ca-certificates.crt" ]; then
            CA_FILE="/etc/ssl/certs/ca-certificates.crt"
        elif [ -f "/etc/ssl/cert.pem" ]; then
            CA_FILE="/etc/ssl/cert.pem"
        fi
    fi
fi

if [ -n "${SSL_CERT_DIR:-}" ] && [ -d "$SSL_CERT_DIR" ]; then
    CA_DIR="$SSL_CERT_DIR"
else
    CA_DIR="$OPENSSL_DIR/certs"

    if [ ! -d "$CA_DIR" ] && [ -d "/etc/ssl/certs" ]; then
        CA_DIR="/etc/ssl/certs"
    fi
fi

echo "CA file:       $CA_FILE"
echo "CA directory:  $CA_DIR"
echo

if [ ! -f "$CA_FILE" ] && [ ! -d "$CA_DIR" ]; then
    echo "ERROR: system CA store not found." >&2
    exit 1
fi

# ============================================================================
# Helper: extract certificates from PEM file
# ============================================================================

extract_certs()
{
    input="$1"
    prefix="$2"

    awk -v prefix="$prefix" '
        /-----BEGIN CERTIFICATE-----/ {
            inside = 1
            cert = ""
        }

        inside {
            cert = cert $0 "\n"
        }

        /-----END CERTIFICATE-----/ {
            inside = 0

            file = sprintf("%s_%04d.pem", prefix, count)
            print cert > file
            close(file)

            count++
        }
    ' "$input"
}

# ============================================================================
# Helper: print certificate information
# ============================================================================

print_cert_info()
{
    cert="$1"

    openssl x509 \
        -in "$cert" \
        -noout \
        -subject \
        -issuer \
        -dates
}

# ============================================================================
# Helper: convert certificate to DER and save it using certificate name
# and SHA-256 fingerprint
# ============================================================================

save_cert()
{
    cert="$1"

    #
    # Get SHA-256 fingerprint from the DER representation.
    #

    fingerprint=$(
        openssl x509 \
            -in "$cert" \
            -outform DER 2>/dev/null |
        openssl dgst -sha256 |
        awk '{print $NF}'
    )

    #
    # Get the certificate Common Name.
    #

    common_name=$(
        openssl x509 \
            -in "$cert" \
            -noout \
            -subject \
            -nameopt RFC2253 2>/dev/null |
        sed -n 's/^subject=.*CN=\([^,]*\).*$/\1/p'
    )

    #
    # If CN cannot be extracted, use "certificate".
    #

    if [ -z "$common_name" ]; then
        common_name="certificate"
    fi

    #
    # Make the name safe for use as a filename.
    #
    # Replace everything except letters, numbers, dots, underscores
    # and hyphens with underscores.
    #

    common_name=$(
        printf '%s' "$common_name" |
        sed 's/[^A-Za-z0-9._-]/_/g'
    )

    #
    # Keep the filename reasonably short.
    #

    common_name=$(printf '%s' "$common_name" | cut -c1-80)

    #
    # Use the first 16 characters of SHA-256 as an additional unique ID.
    #

    short_fingerprint=$(printf '%s' "$fingerprint" | cut -c1-16)

    output="$CERTS_DIR/${common_name}_${short_fingerprint}.der"

    if [ -f "$output" ]; then
        echo "  Already saved: $(basename "$output")"
        return
    fi

    openssl x509 \
        -in "$cert" \
        -outform DER \
        -out "$output"

    echo "  Saved: $(basename "$output")"
}

# ============================================================================
# Process every host
# ============================================================================

for host in $HOSTS; do

    case "$host" in
        *:*)
            hostname="${host%:*}"
            port="${host##*:}"
            ;;
        *)
            hostname="$host"
            port="443"
            ;;
    esac

    echo "======================================================================"
    echo "Host: $hostname:$port"
    echo "======================================================================"

    server_output="$TMP_DIR/${hostname}_s_client.txt"
    server_chain="$TMP_DIR/${hostname}_chain.pem"

    #
    # Obtain the certificates sent by the server.
    #
    # We intentionally do NOT use the returned certificates as trust
    # anchors. They are only the "untrusted" part of the chain.
    #

    if ! openssl s_client \
        -connect "$hostname:$port" \
        -servername "$hostname" \
        -showcerts \
        -verify 10 \
        -verify_return_error \
        </dev/null >"$server_output" 2>&1
    then
        echo "ERROR: TLS connection or certificate verification failed."
        echo
        sed -n '/Verify return code/,$p' "$server_output" || true
        echo
        continue
    fi

    #
    # Extract all certificates sent by the server.
    #

    extract_certs \
        "$server_output" \
        "$TMP_DIR/${hostname}_server"

    first_cert="$TMP_DIR/${hostname}_server_0000.pem"

    if [ ! -f "$first_cert" ]; then
        echo "ERROR: server did not send a certificate."
        echo
        continue
    fi

    #
    # Build a PEM containing all server-supplied certificates.
    #

    : > "$server_chain"

    i=0

    while :; do
        cert="$TMP_DIR/${hostname}_server_$(printf '%04d' "$i").pem"

        if [ ! -f "$cert" ]; then
            break
        fi

        cat "$cert" >> "$server_chain"

        i=$((i + 1))
    done

    echo "Server certificates: $i"
    echo

    echo "Leaf certificate:"
    print_cert_info "$first_cert"
    echo

    # =========================================================================
    # Verify the server chain using the SYSTEM trust store.
    # =========================================================================

    verify_output="$TMP_DIR/${hostname}_verify.txt"

    verify_ok=0

    if [ -f "$CA_FILE" ]; then

        if openssl verify \
            -CAfile "$CA_FILE" \
            -untrusted "$server_chain" \
            -show_chain \
            -verify_hostname "$hostname" \
            "$first_cert" >"$verify_output" 2>&1
        then
            verify_ok=1
        fi

    elif [ -d "$CA_DIR" ]; then

        if openssl verify \
            -CApath "$CA_DIR" \
            -untrusted "$server_chain" \
            -show_chain \
            -verify_hostname "$hostname" \
            "$first_cert" >"$verify_output" 2>&1
        then
            verify_ok=1
        fi

    fi

    if [ "$verify_ok" -ne 1 ]; then
        echo "ERROR: system OpenSSL could not verify $hostname."
        echo
        cat "$verify_output"
        echo
        continue
    fi

    echo "System verification: OK"
    echo
    echo "Built chain:"
    cat "$verify_output"
    echo

    # =========================================================================
    # Find the ROOT certificate.
    #
    # The root normally isn't sent by the server.
    #
    # We therefore search the SYSTEM trust store for a self-signed CA that
    # matches the final issuer of the verified chain.
    # =========================================================================

    #
    # First determine the issuer of the highest certificate sent by the server.
    #

    last_index=$((i - 1))

    last_cert="$TMP_DIR/${hostname}_server_$(printf '%04d' "$last_index").pem"

    last_subject=$(
        openssl x509 \
            -in "$last_cert" \
            -noout \
            -subject
    )

    last_issuer=$(
        openssl x509 \
            -in "$last_cert" \
            -noout \
            -issuer
    )

    echo "Last server certificate:"
    echo "  $last_subject"
    echo "  $last_issuer"
    echo

    #
    # If the last server certificate is already self-signed, it can itself
    # be the trust anchor. Otherwise we need to locate its issuer.
    #

    last_subject_name=$(
        openssl x509 \
            -in "$last_cert" \
            -noout \
            -subject \
            -nameopt RFC2253 |
        sed 's/^subject=//'
    )

    last_issuer_name=$(
        openssl x509 \
            -in "$last_cert" \
            -noout \
            -issuer \
            -nameopt RFC2253 |
        sed 's/^issuer=//'
    )

    root_candidate=""

    #
    # Case 1:
    #
    # The server itself sent a self-signed root.
    #

    if [ "$last_subject_name" = "$last_issuer_name" ]; then
        root_candidate="$last_cert"
    fi

    #
    # Case 2:
    #
    # Search the system CA file.
    #
    # This is deliberately done certificate-by-certificate.
    #

    if [ -z "$root_candidate" ] && [ -f "$CA_FILE" ]; then

        extract_certs \
            "$CA_FILE" \
            "$TMP_DIR/${hostname}_system_ca"

        j=0

        while :; do
            candidate="$TMP_DIR/${hostname}_system_ca_$(printf '%04d' "$j").pem"

            if [ ! -f "$candidate" ]; then
                break
            fi

            subject=$(
                openssl x509 \
                    -in "$candidate" \
                    -noout \
                    -subject \
                    -nameopt RFC2253 2>/dev/null |
                sed 's/^subject=//'
            )

            if [ "$subject" = "$last_issuer_name" ]; then

                #
                # Make sure this is actually a self-signed root.
                #

                issuer=$(
                    openssl x509 \
                        -in "$candidate" \
                        -noout \
                        -issuer \
                        -nameopt RFC2253 2>/dev/null |
                    sed 's/^issuer=//'
                )

                if [ "$subject" = "$issuer" ]; then
                    root_candidate="$candidate"
                    break
                fi
            fi

            j=$((j + 1))
        done
    fi

    #
    # Case 3:
    #
    # Search certificates in the system CA directory.
    #

    if [ -z "$root_candidate" ] && [ -d "$CA_DIR" ]; then

        for candidate in "$CA_DIR"/*; do

            [ -f "$candidate" ] || continue

            #
            # Ignore files which aren't certificates.
            #

            if ! openssl x509 \
                -in "$candidate" \
                -noout >/dev/null 2>&1
            then
                continue
            fi

            subject=$(
                openssl x509 \
                    -in "$candidate" \
                    -noout \
                    -subject \
                    -nameopt RFC2253 2>/dev/null |
                sed 's/^subject=//'
            )

            if [ "$subject" != "$last_issuer_name" ]; then
                continue
            fi

            issuer=$(
                openssl x509 \
                    -in "$candidate" \
                    -noout \
                    -issuer \
                    -nameopt RFC2253 2>/dev/null |
                sed 's/^issuer=//'
            )

            if [ "$subject" = "$issuer" ]; then
                root_candidate="$candidate"
                break
            fi
        done
    fi

    # =========================================================================
    # Save the root certificate.
    # =========================================================================

    if [ -z "$root_candidate" ]; then
        echo "WARNING: could not locate the root CA in the system store."
        echo "The system successfully verified the certificate chain,"
        echo "but the root certificate could not be extracted."
        echo
        continue
    fi

    echo "Root CA:"
    print_cert_info "$root_candidate"
    echo

    save_cert "$root_candidate"

    echo
done

# ============================================================================
# Result
# ============================================================================

echo "======================================================================"
echo "Result"
echo "======================================================================"

count=0

for cert in "$CERTS_DIR"/*.der; do

    [ -f "$cert" ] || continue

    count=$((count + 1))

    echo
    echo "Certificate: $(basename "$cert")"

    openssl x509 \
        -inform DER \
        -in "$cert" \
        -noout \
        -subject \
        -issuer \
        -dates \
        -fingerprint -sha256
done

echo
echo "Total root certificates: $count"
echo

if [ "$count" -eq 0 ]; then
    echo "ERROR: no root certificates were extracted."
    exit 1
fi

echo "Certificates saved to:"
echo "  $CERTS_DIR"
