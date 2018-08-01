FROM node:8.9.3-alpine

# prepare app directory
RUN mkdir -p /usr/src/app

WORKDIR /tmp
COPY ./package.json /tmp
RUN npm install --production

# copy code and delete local modules
COPY . /usr/src/app
WORKDIR /usr/src/app
RUN rm -rf /usr/src/app/node_modules

# copying production modules
WORKDIR /tmp
RUN cp -r node_modules /usr/src/app/node_modules || true

# expose service port
EXPOSE 8800

# starting service
WORKDIR /usr/src/app
CMD [ "npm", "run", "start" ]
