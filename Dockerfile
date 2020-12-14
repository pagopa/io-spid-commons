FROM circleci/node:10.14.2 as builder

WORKDIR /home/circleci

COPY src src
COPY package.json package.json
COPY tsconfig.json tsconfig.json
COPY yarn.lock yarn.lock

RUN mkdir certs \
  && openssl req -nodes \
                 -new \
                 -x509 \
                 -sha256 \
                 -days 365 \
                 -newkey rsa:2048 \
                 -subj "/C=IT/ST=State/L=City/O=Acme Inc. /OU=IT Department/CN=spid-express.selfsigned.example" \
                 -keyout certs/key.pem \
                 -out certs/cert.pem \
  && yarn install \
  && yarn build

FROM node:10.14.2-alpine
LABEL maintainer="https://developers.italia.it"

WORKDIR /usr/src/app

COPY /package.json /usr/src/app/package.json
COPY --from=builder /home/circleci/src /usr/src/app/src
COPY --from=builder /home/circleci/dist /usr/src/app/dist
COPY --from=builder /home/circleci/certs /usr/src/app/certs
COPY --from=builder /home/circleci/node_modules /usr/src/app/node_modules

EXPOSE 3000

CMD ["yarn", "dev"]
