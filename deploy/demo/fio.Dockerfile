# small image for the demo pods and for capturing iostat next to them
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends fio sysstat \
    && rm -rf /var/lib/apt/lists/*
