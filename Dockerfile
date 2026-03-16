FROM python:3.13-slim

LABEL maintainer="cvemula1"
LABEL description="NHInsight — Non-Human Identity discovery CLI"

WORKDIR /app

# Pull OS security patches
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# Install all providers
COPY pyproject.toml setup.py README.md LICENSE ./
COPY nhinsight/ nhinsight/
RUN pip install --no-cache-dir ".[all]"

ENTRYPOINT ["nhinsight"]
CMD ["--help"]
