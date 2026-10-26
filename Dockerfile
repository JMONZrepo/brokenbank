# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Intentionally vulnerable Dockerfile for comprehensive policy coverage
# Five application servers, seven port listeners: Flask/Gunicorn (8888), Java/Tomcat (8080, host 9999),
# React/Next.js SpaceATM (7777), Live Transaction Ticker (6666), PHP eStatements portal (port 8085),
# plus sshd (22, host 2222) and the in-process OTel Prometheus scrape (9464)
# Using Python 3.11 for PyGremlinBox compatibility + bookworm for OpenJDK 17
FROM python:3.11-bookworm

# Docker policy violations for comprehensive testing

# Running as root user (security risk)
USER root

# Installing packages without version pinning including OpenJDK 17 for Spring4Shell
# Create man directories required by OpenJDK packages on slim images
RUN apt-get update && \
    mkdir -p /usr/share/man/man1 && \
    for i in 1 2 3; do \
        apt-get install -y \
        curl \
        wget \
        git \
        vim \
        sudo \
        ssh \
        cron \
        telnet \
        netcat-openbsd \
        iputils-ping \
        openjdk-17-jdk \
        maven \
        ant \
        supervisor \
        && break || { if [ "$i" -eq 3 ]; then echo "apt-get install failed after 3 attempts"; exit 1; fi; echo "apt-get install attempt $i failed, retrying in 5s..."; sleep 5; }; \
    done && \
    rm -rf /var/lib/apt/lists/*

# Install Node.js 20 LTS for SpaceATM Terminal (React/Next.js)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Setting weak file permissions
RUN chmod 777 /tmp
RUN chmod 755 /etc/passwd

# Installing Apache Tomcat 8.5.0 (highly vulnerable legacy version)
# CVE-2020-1938 (Ghostcat), CVE-2020-9484 (RCE), CVE-2021-25122, CVE-2023-42795, CVE-2023-45648
RUN cd /opt && \
    wget https://archive.apache.org/dist/tomcat/tomcat-8/v8.5.0/bin/apache-tomcat-8.5.0.tar.gz && \
    tar xzvf apache-tomcat-8.5.0.tar.gz && \
    mv apache-tomcat-8.5.0 tomcat && \
    rm apache-tomcat-8.5.0.tar.gz && \
    chmod +x /opt/tomcat/bin/*.sh

# Configure Tomcat with intentionally weak settings
COPY config/tomcat-users.xml /opt/tomcat/conf/tomcat-users.xml
COPY config/context.xml /opt/tomcat/conf/context.xml
COPY config/manager-context.xml /opt/tomcat/webapps/manager/META-INF/context.xml
COPY config/manager-context.xml /opt/tomcat/webapps/host-manager/META-INF/context.xml
COPY config/tomcat-setenv.sh /opt/tomcat/bin/setenv.sh
RUN chmod 644 /opt/tomcat/conf/tomcat-users.xml && \
    chmod 644 /opt/tomcat/conf/context.xml && \
    chmod 644 /opt/tomcat/webapps/manager/META-INF/context.xml && \
    chmod 644 /opt/tomcat/webapps/host-manager/META-INF/context.xml && \
    chmod +x /opt/tomcat/bin/setenv.sh

# Exposing application ports (8888 for Flask/Gunicorn, 8080 for Tomcat - mapped to 9999 externally,
# 7777 for the SpaceATM Terminal - React/Next.js)
# 9464 is the OTel default Prometheus scrape port (poll-based metrics)
# 22 is sshd, genuinely reachable via the leaked deployment key or the weak root password
# 6666 is the Live Transaction Ticker (WebSocket)
# 8085 is the PHP eStatements portal (Apache mod_php, PHP 8.4.26 - PHP2Shell)
EXPOSE 8888 8080 7777 9464 22 6666 8085

# Adding secrets directly in Dockerfile (bad practice)
ENV SECRET_KEY="hardcoded-secret-12345"
ENV DATABASE_PASSWORD="admin123"
ENV API_TOKEN="sk-1234567890abcdef"
ENV SESSION_SECRET="hardcoded-docker-secret-key"
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
ENV OPENAI_API_KEY="sk-1234567890abcdefghijklmnopqrstuvwxyz"
ENV DATABASE_URL="sqlite:////app/instance/database.db"

# Running commands that could be cached with secrets
RUN echo "admin:password123" > /tmp/credentials.txt
RUN chmod 644 /tmp/credentials.txt

# Setting working directory
WORKDIR /app

# Copying application code first
COPY . .

# Generate a real SSH keypair for the "leaked deployment key" story: the
# private half is planted at the exposed git-repo path so an attacker who
# reads it can genuinely authenticate; the public half is pre-trusted for
# root login, simulating an ops team that reused a deployment key as a
# root credential. Also set a weak root password so SSH offers both a
# leaked-key login path and a classic weak-password brute-force path.
RUN mkdir -p /root/.ssh && \
    mkdir -p data/projects/mars-banking-initiative/.ssh && \
    rm -f data/projects/mars-banking-initiative/.ssh/id_rsa \
          data/projects/mars-banking-initiative/.ssh/id_rsa.pub && \
    ssh-keygen -t rsa -b 2048 -N "" -C "ares-deploy@gocortex.io" \
        -f data/projects/mars-banking-initiative/.ssh/id_rsa && \
    cat data/projects/mars-banking-initiative/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys && \
    chmod 700 /root/.ssh && \
    chmod 600 /root/.ssh/authorized_keys && \
    chmod 600 data/projects/mars-banking-initiative/.ssh/id_rsa && \
    chmod 644 data/projects/mars-banking-initiative/.ssh/id_rsa.pub && \
    echo "root:admin123" | chpasswd

# Enable and configure sshd (openssh-server ships in the "ssh" metapackage
# installed above) so the leaked key and the weak root password are both
# genuinely usable login paths, not just artefacts on disk.
COPY config/sshd_brokenbank.conf /etc/ssh/sshd_config.d/99-brokenbank.conf
RUN ssh-keygen -A

# Build SpaceATM Terminal (React/Next.js on port 7777)
WORKDIR /app/react-app
RUN npm install && \
    node scripts/patch-react-server-dom.js && \
    node scripts/patch-csrf-origin-check.js && \
    npm run build

# Install the Live Transaction Ticker service (WebSocket, port 6666).
# Pinned to ws 8.17.0 - vulnerable to CVE-2024-37890 (DoS via many HTTP
# headers on the handshake) - not just an application-level misconfiguration.
WORKDIR /app/ticker-service
RUN npm install

WORKDIR /app

# Installing Python packages with vulnerable/older versions for security testing
#
# Wrapped in the same retry/backoff pattern as the apt and llama-cpp-python
# layers. Several of these pins predate Python 3.11 and so have no matching
# wheel - Pillow 8.1.0 in particular is fetched as a 44.9 MB source tarball
# and built from source. On a slow or congested link that download exceeds
# pip's 15-second default read timeout and fails the whole layer, so the
# timeout and retry counts are raised and the install is re-attempted.
RUN for i in 1 2 3; do \
    pip install --no-cache-dir \
    --timeout 300 \
    --retries 5 \
    flask==2.0.1 \
    flask-sqlalchemy==2.5.1 \
    requests==2.25.1 \
    pyjwt==1.7.1 \
    cryptography==39.0.0 \
    pyyaml==6.0 \
    gunicorn==20.1.0 \
    werkzeug==2.0.1 \
    ldap3==2.8.1 \
    pymongo==3.12.0 \
    urllib3==1.26.5 \
    flask-login==0.5.0 \
    email-validator==1.1.3 \
    jinja2==3.0.1 \
    pillow==8.1.0 \
    sqlalchemy==1.4.23 \
    faker==18.13.0 \
    graphql-core==2.3.2 \
    graphene==2.1.9 \
    flask-graphql==2.0.1 \
    opentelemetry-sdk==1.41.0 \
    opentelemetry-exporter-prometheus==0.62b0 \
    prometheus-client==0.20.0 \
    pygremlinbox-agpl-1-0==1.4.6 \
    pygremlinbox-agpl-1-0-only==1.4.6 \
    pygremlinbox-agpl-1-0-or-later==1.4.6 \
    pygremlinbox-agpl-3-0==1.4.6 \
    pygremlinbox-agpl-3-0-only==1.4.6 \
    pygremlinbox-agpl-3-0-or-later==1.4.6 \
    pygremlinbox-apsl==1.4.6 \
    pygremlinbox-arphic-1999==1.4.6 \
    pygremlinbox-artistic-1-0==1.4.6 \
    pygremlinbox-busl-1-1==1.4.6 \
    pygremlinbox-c-uda-1-0==1.4.6 \
    pygremlinbox-cal-1-0-combined-work-exception==1.4.6 \
    pygremlinbox-cc-by-nc-3-0-de==1.4.6 \
    pygremlinbox-cc-by-nc-nd-3-0-de==1.4.6 \
    pygremlinbox-cc-by-nc-nd-3-0-igo==1.4.6 \
    pygremlinbox-cc-by-nc-sa-2-0-de==1.4.6 \
    pygremlinbox-cc-by-nc-sa-2-0-fr==1.4.6 \
    pygremlinbox-cc-by-nc-sa-2-0-uk==1.4.6 \
    pygremlinbox-cc-by-nc-sa-3-0-de==1.4.6 \
    pygremlinbox-cc-by-nc-sa-3-0-igo==1.4.6 \
    pygremlinbox-cc-by-nd-3-0-de==1.4.6 \
    pygremlinbox-cc-by-sa-2-0-uk==1.4.6 \
    pygremlinbox-cc-by-sa-2-1-jp==1.4.6 \
    pygremlinbox-cc-by-sa-3-0-at==1.4.6 \
    pygremlinbox-cc-by-sa-3-0-de==1.4.6 \
    pygremlinbox-cc-by-sa-4-0==1.4.6 \
    pygremlinbox-cddl-1-0==1.4.6 \
    pygremlinbox-cdla-sharing-1-0==1.4.6 \
    pygremlinbox-cern-ohl-s-2-0==1.4.6 \
    pygremlinbox-cern-ohl-w-2-0==1.4.6 \
    pygremlinbox-copyleft-next-0-3-0==1.4.6 \
    pygremlinbox-copyleft-next-0-3-1==1.4.6 \
    pygremlinbox-cpol-1-02==1.4.6 \
    pygremlinbox-ecos-2-0==1.4.6 \
    pygremlinbox-epl-1-0==1.4.6 \
    pygremlinbox-epl-2-0==1.4.6 \
    pygremlinbox-eupl-1-1==1.4.6 \
    pygremlinbox-eupl-1-2==1.4.6 \
    pygremlinbox-eupl-3-0==1.4.6 \
    pygremlinbox-fdk-aac==1.4.6 \
    pygremlinbox-gpl-2-0==1.4.6 \
    pygremlinbox-gpl-3-0==1.4.6 \
    pygremlinbox-hippocratic-2-1==1.4.6 \
    pygremlinbox-jpl-image==1.4.6 \
    pygremlinbox-lgpl-2-0==1.4.6 \
    pygremlinbox-lgpl-2-1==1.4.6 \
    pygremlinbox-lgpl-3-0==1.4.6 \
    pygremlinbox-linux-man-pages-copyleft==1.4.6 \
    pygremlinbox-mpl-1-1==1.4.6 \
    pygremlinbox-mpl-2-0==1.4.6 \
    pygremlinbox-ms-lpl==1.4.6 \
    pygremlinbox-ncgl-uk-2-0==1.4.6 \
    pygremlinbox-openpbs-2-3==1.4.6 \
    pygremlinbox-osl-3-0==1.4.6 \
    pygremlinbox-polyform-noncommercial-1-0-0==1.4.6 \
    pygremlinbox-polyform-small-business-1-0-0==1.4.6 \
    pygremlinbox-qpl-1-0-inria-2004==1.4.6 \
    pygremlinbox-sendmail-8-23==1.4.6 \
    pygremlinbox-simpl-2-0==1.4.6 \
    pygremlinbox-sspl-1-0==1.4.6 \
    pygremlinbox-tapr-ohl-1-0==1.4.6 \
    pygremlinbox-tpl-1-0==1.4.6 \
    pygremlinbox-ucl-1-0==1.4.6 \
    pygremlinbox-unlicense==1.4.6 \
    pygremlinbox-wxwindows==1.4.6 \
    && break || { if [ "$i" -eq 3 ]; then echo "pip install failed after 3 attempts"; exit 1; fi; echo "pip install attempt $i failed, retrying in 10s..."; sleep 10; }; \
    done

# Install llama-cpp-python for whichever architecture the image is being
# built for. On x86_64 the prebuilt PyPI wheel statically compiles GGML
# with AVX/AVX2/F16C/FMA enabled, which is fast on Haswell-or-later hosts
# but SIGILLs the gunicorn worker on older CPUs that do not expose those
# flags; the runtime CPU-feature guard in chatbot/concierge.py disables the
# Concierge entirely on such hosts so the import that would crash never
# runs. On aarch64 (Apple Silicon / ARM cloud) the pinned version may not
# publish a prebuilt PyPI wheel, so we install the build toolchain first,
# let pip use a wheel when one exists or otherwise compile the NEON build
# from source, then purge the toolchain in the same layer to keep the image
# small. See the internal Concierge build notes for the rationale.
#
# The 3-attempt retry loop and extended pip timeouts cover transient PyPI
# fetch failures that have been observed during image builds. The in-layer
# import probe fails the build fast if the module does not import correctly.
RUN ARCH="$(uname -m)"; \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        apt-get update && \
        apt-get install -y --no-install-recommends build-essential cmake && \
        rm -rf /var/lib/apt/lists/*; \
    fi; \
    for i in 1 2 3; do \
        pip install --no-cache-dir \
            --timeout 300 \
            --retries 5 \
            llama-cpp-python==0.3.5 \
        && break || { if [ "$i" -eq 3 ]; then echo "llama-cpp-python install failed after 3 attempts"; exit 1; fi; echo "llama-cpp-python install attempt $i failed, retrying in 10s..."; sleep 10; }; \
    done && \
    python -c "from llama_cpp import Llama; print('llama_cpp import ok')" && \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        apt-get purge -y --auto-remove build-essential cmake || true; \
    fi

# Bake the SmolLM2-135M-Instruct GGUF Q4_K_M weights into the image so the
# Mars Banking Initiative Concierge can run inference without network access
# at runtime. ~88 MB on disk; peak RSS during inference stays well under
# 1.5 GB on a single CPU worker.
#
# This is a mirror of HuggingFaceTB/SmolLM2-135M-Instruct-GGUF
# (smollm2-135m-instruct-q4_k_m.gguf). HuggingFace's anonymous resolve
# endpoint now returns HTTP 401, so a "clone and docker build" workflow
# cannot fetch from huggingface.co directly. We therefore default to a
# GitHub Release asset on this repo (no auth, CDN-backed, doesn't bloat
# the git tree). The SHA256 is pinned and verified after download; the
# build fails fast on mismatch.
#
# To refresh the mirror (new quant or upstream revision):
#   1. Download the file from HuggingFace (huggingface-cli download
#      HuggingFaceTB/SmolLM2-135M-Instruct-GGUF smollm2-135m-instruct-q4_k_m.gguf)
#      and compute its sha256sum.
#   2. Upload it as an asset on a new GitHub Release of this repository.
#   3. Update MODEL_RELEASE_URL and MODEL_SHA256 below.
#
# Three ways to supply a HuggingFace token for the opt-in HF path
# (preferred order, most secure first):
#   1. BuildKit secret (recommended for CI):
#        DOCKER_BUILDKIT=1 docker build \
#          --secret id=hf_token,src=./hf_token.txt -f Dockerfile .
#      The token is mounted into the build at /run/secrets/hf_token,
#      never appears in build-arg history, image layers, or provenance.
#   2. Environment file with --build-arg (less secure, may leak via
#      shell history or CI logs):
#        docker build --build-arg HF_TOKEN=hf_xxx -f Dockerfile .
#   3. No token (default): fetches from the GitHub Release mirror
#      with no credentials.
# MODEL_SHA256 below is the verified SHA256 of the mirrored GGUF release
# asset. The download is checked against it and the build fails fast on
# any mismatch rather than installing an unverified file.
ARG HF_TOKEN=
ARG MODEL_SHA256=2e8040ceae7815abe0dcb3540b9995eaa1fa0d2ca9e797d0a635ae4433c68c2d
ARG MODEL_RELEASE_URL=https://github.com/gocortexio/gocortexbrokenbank/releases/download/v1.5.0-beta.1/SmolLM2-135M-Instruct-Q4_K_M.gguf
ARG MODEL_HF_URL=https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct-GGUF/resolve/main/smollm2-135m-instruct-q4_k_m.gguf
RUN --mount=type=secret,id=hf_token,required=false \
    mkdir -p /opt/models && \
    DEST=/opt/models/smollm2-135m-instruct-q4_k_m.gguf && \
    if [ "$MODEL_SHA256" = "PLACEHOLDER_SET_AFTER_RELEASE_UPLOAD" ]; then \
        echo "ERROR: MODEL_SHA256 is still the placeholder."; \
        echo "Run the bootstrap step in .local/tasks/task-27.md:"; \
        echo "  1. huggingface-cli download HuggingFaceTB/SmolLM2-135M-Instruct-GGUF smollm2-135m-instruct-q4_k_m.gguf --local-dir ."; \
        echo "  2. sha256sum smollm2-135m-instruct-q4_k_m.gguf"; \
        echo "  3. gh release create models-smollm2-135m-q4km-v1 ./smollm2-135m-instruct-q4_k_m.gguf --title 'Concierge model assets v1'"; \
        echo "  4. Replace MODEL_SHA256 in this Dockerfile with the digest from step 2."; \
        exit 1; \
    fi && \
    TOKEN="$HF_TOKEN" && \
    if [ -z "$TOKEN" ] && [ -s /run/secrets/hf_token ]; then \
        TOKEN="$(cat /run/secrets/hf_token)"; \
    fi && \
    if [ -n "$TOKEN" ]; then \
        echo "Fetching GGUF from HuggingFace (token supplied)"; \
        wget -q --header="Authorization: Bearer ${TOKEN}" -O "$DEST" "$MODEL_HF_URL"; \
    else \
        echo "Fetching GGUF from GitHub Release mirror: $MODEL_RELEASE_URL"; \
        wget -q -O "$DEST" "$MODEL_RELEASE_URL"; \
    fi && \
    unset TOKEN && \
    echo "${MODEL_SHA256}  $DEST" | sha256sum -c - && \
    chmod 644 "$DEST"
ENV CONCIERGE_MODEL_PATH=/opt/models/smollm2-135m-instruct-q4_k_m.gguf
# CONCIERGE_MODEL_NAME is deliberately NOT set here. It takes priority over the
# provider-derived name, so baking it in would report the local GGUF even when
# a SaaS provider is answering. chatbot/concierge.py:model_name() already
# returns this same value for the local provider, and the correct upstream
# model for portkey/openrouter. Set it explicitly at run time only to force a
# display name.

# Copying sensitive files after installation
COPY vulnerable_data/ /app/secrets/

# Create instance directory for database with proper permissions
RUN mkdir -p /app/instance && \
    chmod 777 /app/instance && \
    touch /app/instance/database.db && \
    chmod 666 /app/instance/database.db

# Environment variables for Tomcat
ENV CATALINA_HOME=/opt/tomcat
ENV PATH=$PATH:$CATALINA_HOME/bin

# Build Java exploit application WAR file and set JAVA_HOME dynamically
COPY exploit-app /app/exploit-app
WORKDIR /app/exploit-app
RUN export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java)))) && \
    echo "$JAVA_HOME" > /tmp/java_home_path.txt && \
    echo "export JAVA_HOME=$JAVA_HOME" >> /etc/profile && \
    echo "JAVA_HOME=$JAVA_HOME" >> /etc/environment && \
    mvn clean package -DskipTests && \
    cp target/exploit-app.war $CATALINA_HOME/webapps/

# Build evil.jar payload for /dynamic endpoint testing
WORKDIR /app/vulnerable_data/payloads
RUN export JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java)))) && \
    mvn clean package -DskipTests && \
    cp target/evil.jar /app/vulnerable_data/payloads/evil.jar && \
    chmod 644 /app/vulnerable_data/payloads/evil.jar

# Return to app directory
WORKDIR /app

# Installing PHP 8.4.26 from the official upstream source release, built as an
# Apache mod_php module (the SAPI the PHP2Shell advisories flag as highest
# risk). PHP 8.4.26 predates the 8.4.27 fix, so it is affected by PHP2Shell:
#   CVE-2026-109618 and CVE-2026-109619 (both CVSS 9.2, unauthenticated RCE).
# Built from source because every current package feed has already rolled to
# the patched 8.4.27 - the same reason Tomcat 8.5.0 is fetched as a pinned
# upstream tarball rather than from apt. The source tarball is pinned by the
# SHA256 that php.net publishes for this release and verified before build.
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    for i in 1 2 3; do \
        apt-get install -y --no-install-recommends \
        build-essential autoconf pkg-config bison re2c \
        libxml2-dev libsqlite3-dev libssl-dev \
        apache2 apache2-dev \
        && break || { if [ "$i" -eq 3 ]; then echo "php build-deps install failed"; exit 1; fi; echo "retry $i"; sleep 5; }; \
    done && \
    rm -rf /var/lib/apt/lists/* && \
    cd /usr/src && \
    for i in 1 2 3; do \
        wget -q --timeout=300 -O php-8.4.26.tar.gz https://www.php.net/distributions/php-8.4.26.tar.gz \
        && break || { if [ "$i" -eq 3 ]; then echo "php source download failed"; exit 1; fi; echo "retry $i"; sleep 10; }; \
    done && \
    echo "c248abaebc4bb777b80968f0760da0da8e989836e896c9ff637b6775d7d37662  php-8.4.26.tar.gz" | sha256sum -c - && \
    tar xzf php-8.4.26.tar.gz && \
    cd php-8.4.26 && \
    ./configure \
        --with-apxs2=/usr/bin/apxs \
        --enable-opcache \
        --with-openssl \
        --with-config-file-path=/usr/local/php/etc \
        --with-config-file-scan-dir=/usr/local/php/etc/conf.d && \
    make -j"$(nproc)" && \
    make install && \
    mkdir -p /usr/local/php/etc/conf.d && \
    cd /usr/src && rm -rf php-8.4.26 php-8.4.26.tar.gz && \
    /usr/local/bin/php -v

# Deliberately insecure php.ini (upload_progress on, allow_url_include on,
# display_errors on, expose_php on) and the Apache site that serves the portal
# on port 8085. mod_php is non-threadsafe, so Apache must use the prefork MPM.
COPY config/php.ini /usr/local/php/etc/php.ini
COPY config/apache-brokenbank.conf /etc/apache2/sites-available/estatements.conf
RUN a2dismod -f mpm_event >/dev/null 2>&1 || true && \
    a2dismod -f mpm_worker >/dev/null 2>&1 || true && \
    a2enmod mpm_prefork >/dev/null 2>&1 && \
    printf 'LoadModule php_module /usr/lib/apache2/modules/libphp.so\n' > /etc/apache2/mods-available/php.load && \
    ln -sf /etc/apache2/mods-available/php.load /etc/apache2/mods-enabled/php.load && \
    a2ensite estatements >/dev/null 2>&1 && \
    mkdir -p /var/log/apache2

# The portal application (COPY . . above placed it at /app/php-portal). The
# uploads directory is created here rather than shipped in git: the repo's
# .gitignore drops "uploads/", so the directory is not in the checkout and
# must be made in the image. It is world-writable so mod_php (www-data) can
# write to it.
COPY php-portal/ /var/www/html/
RUN mkdir -p /var/www/html/uploads && \
    chmod -R 777 /var/www/html/uploads && \
    chown -R www-data:www-data /var/www/html

# Create supervisor configuration for multi-service startup (gunicorn, tomcat, log-forwarder,
# spaceatm, sshd, cron, ticker, php-apache)
RUN mkdir -p /var/log/supervisor
COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# supervisord runs as root and launches every service: Flask/Gunicorn (8888, with the in-process
# OTel scrape on 9464), Tomcat (8080), SpaceATM (7777), Live Transaction Ticker (6666),
# PHP eStatements portal (port 8085), sshd (22), log-forwarder and cron
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

# Health check with potential information disclosure (checks Flask 8888, Tomcat 8080 and SpaceATM 7777)
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8888/ && curl -f http://localhost:8080/ && curl -f http://localhost:7777/ || exit 1