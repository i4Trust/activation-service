FROM node:14

# User
RUN groupadd --gid 5000 aservice \
    && useradd --home-dir /home/aservice --create-home --uid 5000 \
        --gid 5000 --shell /bin/sh --skel /dev/null aservice
COPY . /home/aservice
WORKDIR /home/aservice

# npm
RUN npm install

# chown
RUN chown aservice /home/aservice
RUN chmod a+rw /home/aservice
USER aservice
WORKDIR /home/aservice
RUN npm install

# Start
EXPOSE 7000
CMD [ "npm", "start" ]
