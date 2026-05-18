FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends xinetd \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --home-dir /home/ctf --shell /usr/sbin/nologin ctf

WORKDIR /app
COPY share/src/ /app/
COPY share/run /app/run
COPY xinetd.conf /etc/xinetd.conf
COPY app.xinetd /etc/xinetd.d/app

RUN chmod 0555 /app/run /app/server.py \
    && chmod -R a-w /app \
    && chown -R root:root /app /etc/xinetd.conf /etc/xinetd.d/app

EXPOSE 5000

USER ctf

CMD ["xinetd", "-dontfork", "-f", "/etc/xinetd.conf"]