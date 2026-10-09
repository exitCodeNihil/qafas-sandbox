FROM node:22-bookworm
RUN npm i -g pnpm
RUN pip install --no-cache-dir 'requests' 'it'\''s'
RUN npm install -g 'typescript' '@types/node'
WORKDIR /w
ENV K="v"
ENV A="b c"
RUN mkdir -p "$(dirname '/etc/m o'\''tď')" && echo 'aMOpbGxvICd3w7ZybGQnCg==' | base64 -d > '/etc/m o'\''tď'
