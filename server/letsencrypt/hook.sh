#!/bin/bash
set -e

HTDOCS_PATH_REL=../htdocs

function auth_http {
    mkdir -p ${CHALLENGE_DIR_PATH}
    echo ${CERTBOT_VALIDATION} > ${CHALLENGE_DIR_PATH}/${CERTBOT_TOKEN}
}

function clean_http {
    rm -f ${CHALLENGE_DIR_PATH}/${CERTBOT_TOKEN}
}

function auth_dns {
    echo "TODO: auth_dns"
}

function clean_dns {
    echo "TODO: clean_dns"
}

function error {
    echo "... something went wrong!"
    exit 1
}

function verify_parameters {
    AUTH="auth"
    CLEAN="clean"
    HTTP="http"
    DNS="dns"
    COMMANDS_REGEX="^(${AUTH}$|${CLEAN}$)"
    AUTH_REGEX="^(${HTTP}$|${DNS}$)"
    if ! [[ ${REQ} =~ ${COMMANDS_REGEX} && ${METHOD} =~ ${AUTH_REGEX} ]]; then
        echo ""
        echo "Rx'd : hook.sh '${REQ}' '${METHOD}'"
        echo ""

        echo "Usage: hook.sh 'auth|clean' 'http|dns'"
        echo "e.g.   hook.sh auth http"
        echo ""
        exit 1
    fi

    if [[ -z ${CERTBOT_VALIDATION} ]]; then
        echo "ERROR: CERTBOT_VALIDATION not set!"
        exit 1
    fi

    if [[ -z ${CERTBOT_TOKEN} ]]; then
        echo "ERROR: CERTBOT_TOKEN not set!"
        exit 1
    fi
}

function main {
    case ${REQ} in
        ${AUTH})
            case ${METHOD} in
                ${HTTP})
                    auth_http
                    ;;
                ${DNS})
                    auth_dns
                    ;;
                *)
                    error
                    ;;
            esac
            ;;
        ${CLEAN})
            case ${METHOD} in
                ${HTTP})
                    clean_http
                    ;;
                ${DNS})
                    clean_dns
                    ;;
                *)
                    error
                    ;;
            esac
            ;;
        *)
            error
            ;;
    esac
}

##############################################################################

REQ=${1}
METHOD=${2}
SCRIPTPATH=$( cd "$(dirname "$0")" ; pwd -P )
CHALLENGE_DIR_PATH=${SCRIPTPATH}/${HTDOCS_PATH_REL}/.well-known/acme-challenge

verify_parameters
main
