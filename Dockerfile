FROM python:3.8-slim

# install curl and jq
RUN apt-get update && apt-get install -y curl jq

# install sops
RUN curl -OL https://github.com/mozilla/sops/releases/download/v3.7.3/sops_3.7.3_amd64.deb \
    && apt-get -y install ./sops_3.7.3_amd64.deb \
    && rm sops_3.7.3_amd64.deb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD [ "./build-script.sh" ]