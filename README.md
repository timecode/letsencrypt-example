# Let's Encrypt Example

_Using [Let's Encrypt](https://letsencrypt.org/) to generate TLS certificates_

The [`certbot`](https://certbot.eff.org/) command automates the process of acquiring Let's Encrypt certificates for a given website. Similarly, [`cert-manager`](https://github.com/jetstack/cert-manager) automates the provision and management of TLS certificates in Kubernetes (using issuers such as Let's Encrypt).

## Proving Domain Ownership

Let's Encrypt uses challenges to verify that you own the domain that you're trying to acquire a certificate for. Currently there are two different challenge types, `http-01` and `dns-01`.

-   `http-01`: create a file in a well-known directory structure within your website, containing a challenge string that the API provides.
-   `dns-01`: create a TXT record in the DNS settings for your domain, containing a challenge string that the API provides.

Let`s Encrypt will then look for the file or TXT record. If the file is there and contains the correct challenge string, Let's Encrypt will the allow you to obtain a certificate for a provided CSR.

## Obtaining a Certificate

Let's Encrypt provides an ACMEv2 API. The ACME (Automatic Certificate Management Environment) protocol defines how a Certificate Authority (CA) can automate the verification step for domain ownership.

### Workflow

1.  Make a request (an order) to generate a certificate for one or more domain names.
2.  The response (authorization(s)), contains one or more challenges for each domain name in the order.
3.  Install challenges using either `http-01` or `dns-01` targets.
4.  Wait, for files to distribute to endpoints or for DNS to propagate for all domains. You get one chance to validate an order and a failure of just one domain means starting all over.
5.  Make a request to validate that the challenges were installed successfully.
6.  Finalize the order by sending a Certificate Signing Request (CSR) containing the required domain names.
7.  The response is a signed certificate, valid for all of the domain names verified and sent with the CSR.

### Wildcard certificates

Instead of listing individual domains in the certificate request you can ask for a wildcard, like this:

```txt
example.com
*.example.com
```

LetsEncrypt will give two challenges for the same domain name because it wants to verify both the root and the wildcard. See [Wildcard Wrinkle](https://www.petekeen.net/lets-encrypt-without-certbot) for details of issues with AWS Route53.

## Practical Example

### Pre-requisites

1.  Use `openresty`

    ```sh
    brew install openresty
    ```

2.  Setup directory structure, if required

    ```sh
    mkdir letsencrypt-example

    cd letsencrypt-example

    mkdir -p server/{logs,tmp,htdocs,ssl}

    touch server/{nginx.conf,htdocs/{favicon.ico,index.html},letsencrypt/hook.sh}
    ```

3.  Add server config `server/nginx.conf`.

    **Note**: `http` is serverd on port `8080` and `https` is serverd on port `8443`

    ```nginx
    worker_processes              1;
    error_log                     server/logs/error.log;
    events {
      worker_connections          1024;
    }
    http {
      client_body_temp_path       server/tmp/client_body_temp/;
      proxy_temp_path             server/tmp/proxy_temp/;
      fastcgi_temp_path           server/tmp/fastcgi_temp/;
      scgi_temp_path              server/tmp/scgi_temp/;
      uwsgi_temp_path             server/tmp/uwsgi_temp/;

      log_format timed_combined   'nginx:$nginx_version '
                                  '$remote_addr - $remote_user [$time_local] '
                                  '"$request" $status $body_bytes_sent '
                                  'REFERER:"$http_referer" USER_AGENT:"$http_user_agent" '
                                  'REQ_T=$request_time RESP_T=$upstream_response_time PIPE=$pipe';

      log_format ssl_client       'nginx:$nginx_version '
                                  '$remote_addr - $remote_user [$time_local] '
                                  '"$request" $status $body_bytes_sent '
                                  'REFERER:"$http_referer" USER_AGENT:"$http_user_agent" '
                                  'REQ_T=$request_time RESP_T=$upstream_response_time PIPE=$pipe '
                                  '"Issuer DN" $ssl_client_i_dn '
                                  '"Client DN" $ssl_client_s_dn '
                                  '"Client fingerprint" $ssl_client_fingerprint';
      server {
        # SET TO DOMAIN BEING (FAKE) SERVED !!!
        server_name               382d99a2.ngrok.io;

        listen                    8080;
        listen                    [::]:8080;

        access_log                server/logs/access.log timed_combined;

        # IF TLS CERTS ARE PRESENT, UNCOMMENT THE NEXT LINE TO PROVE REDIRECTION...
        # return                    301 https://$server_name:8443$request_uri;

        root                      server/htdocs/;
        index                     index.html index.htm;
        location / {
          try_files               $uri $uri/ =404;
        }
        location /hello {
          default_type            text/plain;
          echo                    "hello, world!";
        }
        location /favicon.ico {
          alias                   server/htdocs/favicon.ico;
        }
      }

      # # IF TLS CERTS ARE PRESENT, UNCOMMENT THE WHOLE OF THIS SECTION...
      # server {
      #   # SET TO DOMAIN BEING (FAKE) SERVED !!!
      #   server_name               382d99a2.ngrok.io;

      #   listen                    8443 ssl http2 default_server;
      #   listen                    [::]:8443 ssl http2 default_server;

      #   access_log                server/logs/access.log ssl_client;

      #   ssl_certificate           ssl/server-cert.pem;
      #   ssl_certificate_key       ssl/server-key.pem;

      #   # include snippets/ssl-params.conf;
      #   # https://cipherli.st/
      #   ssl_protocols             TLSv1.2;        # nginx >= 1.13.0 else use TLSv1.2
      #   ssl_prefer_server_ciphers on;
      #   ssl_ciphers               EECDH+AESGCM:EDH+AESGCM;
      #   ssl_ecdh_curve            secp384r1;
      #   # ssl_dhparam               ssl/dhparam.pem; # openssl dhparam -out conf/dhparam.pem 4096
      #   ssl_session_timeout       10m;
      #   ssl_session_cache         shared:SSL:10m;
      #   ssl_session_tickets       off;
      #   ssl_stapling              on;
      #   ssl_stapling_verify       on;
      #   resolver                  1.1.1.1 8.8.8.8 valid=300s;
      #   resolver_timeout          5s;
      #   add_header                Strict-Transport-Security "max-age=63072000;   includeSubDomains; preload";
      #   add_header                X-Frame-Options DENY;
      #   add_header                X-Content-Type-Options nosniff;
      #   add_header                X-XSS-Protection "1; mode=block";

      #   ##########################################################################
      #   # CONTENT
      #   root                      server/htdocs;
      #   index                     index.html index.htm;
      #   location / {
      #     try_files               $uri $uri/ =404;
      #   }
      #   location /hello {
      #     default_type            text/plain;
      #     echo                    "hello, world!";
      #   }
      #   location /favicon.ico {
      #     alias                   server/htdocs/favicon.ico;
      #   }
      # }
    }
    ```

4.  Add Let's Encrypt hook `server/letsencrypt/hook.sh`.

    ```sh
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
    ```

5.  Add a simple HTML index page `server/htdocs/index.html`.

    ```html
    <!DOCTYPE html>
    <html>
      <head>
        <title>Welcome</title>
        <style>
          body {
            width: 35em;
            margin: 0 auto;
            font-family: sans-serif;
          }
        </style>
      </head>

      <body>
        <h1>Welcome</h1>
        <p>Everything appears to be working!</p>
      </body>
    </html>
    ```

6.  Note `openresty` commands to `start`/`reload`/`quit` the local server as and when required, below.

    ```sh
    openresty -p `pwd`/ -c server/nginx.conf

    # after modifying the nginx.conf
    openresty -s reload

    # to stop openresty
    openresty -s quit
    ```

7.  Verify the server is working locally, with non-TLS communication (regular `http`).

    ```sh
    curl -vvv http://127.0.0.1:8080/hello

    *   Trying 127.0.0.1...
    * TCP_NODELAY set
    * Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
    > GET /hello HTTP/1.1
    > Host: 127.0.0.1:8080
    > User-Agent: curl/7.64.1
    > Accept: */*
    >
    < HTTP/1.1 200 OK
    < Server: openresty/1.15.8.2
    < Content-Type: text/plain
    < Transfer-Encoding: chunked
    < Connection: keep-alive
    <
    hello, world!
    * Connection #0 to host 127.0.0.1 left intact
    * Closing connection 0
    ```

### Adding TLS using Let's Encrypt

In this example we won't need direct access to a real server or DNS. We'll setup a server locally then use `ngrok` to expose a public URL which Let's Encrypt will then be ale to access the local server over.

1.  Invoke ngrok to make the local server (on port 8080) available from the Internet (on port 80).

    ```sh
    # note, we don't need ngrok to give a TLS/https route
    ngrok http --bind-tls "false" 8080
    ```

    Make a note the public address provided, such as `http://382d99a2.ngrok.io`, and export the domain to an ENV

    ```sh
    export CERTBOT_DOMAIN=382d99a2.ngrok.io
    ```

2.  Obtain a cert for the domain.

    The following example uses Let's Encrypt's `http` challenge-response method...

    ```sh
    CHALLENGE=http; \
    sudo certbot certonly \
        --non-interactive \
        --manual \
        --manual-public-ip-logging-ok \
        --domain                ${CERTBOT_DOMAIN} \
        --preferred-challenges  ${CHALLENGE} \
        --manual-auth-hook      "server/letsencrypt/hook.sh auth ${CHALLENGE}" \
        --manual-cleanup-hook   "server/letsencrypt/hook.sh clean ${CHALLENGE}"

    # if curious about the CSR created,
    # look at the newest CSR in /etc/letsencrypt/csr/, such as...
    CSR_PATH=/etc/letsencrypt/csr/0001_csr-certbot.pem ;\
    openssl req \
        -noout \
        -text \
        -in ${CSR_PATH}
    ```

3.  Now that we've finished with Let's Encrypt, we can stop the `ngrok` service (`ctrl-C`).

4.  Copy the generated certs to the local server.

    ```sh
    sudo cp \
        /etc/letsencrypt/live/${CERTBOT_DOMAIN}/fullchain.pem \
        server/ssl/server-cert.pem && \
    sudo cp \
        /etc/letsencrypt/live/${CERTBOT_DOMAIN}/privkey.pem \
        server/ssl/server-key.pem
    ```

5.  Fix certificate permissions/ownership.

    ```sh
    sudo chown $USER server/ssl/*.pem
    ```

6.  Uncomment the SSL section of `nginx.conf`.

7.  Reload nginx.

    ```sh
    openresty -s reload
    ```

8.  Ensure we now intercept traffic to the domain by modifying `/etc/hosts`.

    ```sh
    echo ${CERTBOT_DOMAIN}
    # e.g. 382d99a2.ngrok.io

    sudo vi /etc/hosts
    ```

    ... add a line, similar to the following, to the end of the `/etc/hosts` file

    ```txt
    127.0.0.1    382d99a2.ngrok.io
    ```

### Verify the server is working for non-TLS AND TLS communication

Access the site (locally, as `/etc/hosts` is redirecting requests)

```sh
# http, on port 8080
curl -vvv http://${CERTBOT_DOMAIN}:8080/hello

# and, of course, https, on port 8443...
curl -vvv https://${CERTBOT_DOMAIN}:8443/hello
```

Note the TLS negotiations in the output, as well as verification of the certificate. If connecting using a browser, check the TLS certificate in more detail.

### Teardown

When done, the certs may be revoked...

```sh
sudo certbot revoke \
    --non-interactive \
    --cert-name ${CERTBOT_DOMAIN}
```

## Resources

-   [OpenResty](https://openresty.org/en/installation.html)

-   [OpenRestyecho-nginx-module](https://github.com/openresty/echo-nginx-module#readme)

-   [An-Introduction-To-OpenResty](http://openmymind.net/An-Introduction-To-OpenResty-Part-3/)

-   [OpenResty Reference / Lua Ngx API](https://openresty-reference.readthedocs.io/en/latest/Lua_Nginx_API/)

-   [Interactive Message Adapter for Node and Express](https://github.com/slackapi/node-slack-interactive-messages#configuration)

-   [NGROK - real-time web UI / HTTP traffic introspector](https://dashboard.ngrok.com)

    -   See [get started](https://dashboard.ngrok.com/get-started)

-   [lets-encrypt-without-certbot](https://www.petekeen.net/lets-encrypt-without-certbot)

-   [istio-cert-manager-lets-encrypt-demystified](https://medium.com/@gregoire.waymel/istio-cert-manager-lets-encrypt-demystified-c1cbed011d67)
