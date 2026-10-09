FROM python:3.12-slim
RUN apt-get update
WORKDIR /work
ENV A="1"
ENV B="two words"
RUN pip install --no-cache-dir 'requests' 'it'\''s'
RUN npm install -g 'left-pad'
RUN mkdir -p "$(dirname '/etc/app/conf.txt')" && echo 'aGVsbG8gJ3dvcmxkJwrDvG7Drw==' | base64 -d > '/etc/app/conf.txt'
