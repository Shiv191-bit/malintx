# MALINT-X container. Tool versions match those verified on the dev host (JADX 1.5.6, Apktool 3.0.3).
FROM python:3.14-slim AS base

ARG JADX_VERSION=1.5.6
ARG APKTOOL_VERSION=3.0.3
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1

# JRE for the optional JADX/Apktool adapters. Pin and verify tool archives for your own deployment
# (add `echo "<sha256>  file" | sha256sum -c -` once you have vetted a release).
RUN apt-get update && apt-get install -y --no-install-recommends default-jre-headless curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/jadx /opt/apktool \
    && curl -fsSL -o /tmp/jadx.zip "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
    && unzip -q /tmp/jadx.zip -d /opt/jadx && rm /tmp/jadx.zip \
    && curl -fsSL -o /opt/apktool/apktool.jar "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
    && printf '#!/bin/sh\nexec java -jar /opt/apktool/apktool.jar "$@"\n' > /usr/local/bin/apktool && chmod +x /usr/local/bin/apktool

# Unprivileged runtime user; the sample store and database live on a volume.
RUN useradd --create-home --uid 10001 malintx
WORKDIR /app
COPY requirements.lock.txt pyproject.toml README.md ./
RUN pip install -r requirements.lock.txt pyzipper
COPY malintx ./malintx
COPY data ./data
COPY scripts ./scripts
COPY .streamlit ./.streamlit
RUN pip install --no-deps .
ENV MALINTX_ASSETS_DIR=/app/data MALINTX_DATA_DIR=/data MALINTX_JADX=/opt/jadx/bin/jadx MALINTX_APKTOOL=/usr/local/bin/apktool MALINTX_API_HOST=0.0.0.0
RUN mkdir /data && chown malintx /data
USER malintx
VOLUME /data
EXPOSE 8750 8501
CMD ["python", "-m", "malintx.api.app"]
