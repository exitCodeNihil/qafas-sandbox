FROM node:22-bookworm
RUN npm i -g pnpm
RUN pip install --no-cache-dir 'requests' 'it'\''s'
RUN npm install -g 'typescript'
WORKDIR /w
ENV K="v"
ENV A="1 2"
ENV B="x"
RUN mkdir -p "$(dirname '/etc/my motd')" && echo 'aGkgJ3RoZXJlJwrDvG7Drw==' | base64 -d > '/etc/my motd'
