FROM circleci/node:10.14.2 as builder

RUN sudo apt-get -y install --no-install-recommends libunwind8=1.1-4.1

WORKDIR /usr/src/app

COPY /src /usr/src/app/src
COPY /package.json /usr/src/app/package.json
COPY /tsconfig.json /usr/src/app/tsconfig.json
COPY /yarn.lock /usr/src/app/yarn.lock

RUN sudo chmod -R 777 /usr/src/app \
  && yarn install \
  && yarn build

FROM node:10.14.2-alpine
LABEL maintainer="https://pagopa.gov.it"

# Install major CA certificates to cover
# https://github.com/SparebankenVest/azure-key-vault-to-kubernetes integration
RUN apk update && \
    apk add ca-certificates

WORKDIR /usr/src/app

COPY /package.json /usr/src/app/package.json
COPY --from=builder /usr/src/app/src /usr/src/app/src
COPY --from=builder /usr/src/app/dist /usr/src/app/dist
COPY --from=builder /usr/src/app/node_modules /usr/src/app/node_modules

EXPOSE 3000

CMD ["yarn", "dev"]
