FROM node:latest
ENV NODE_ENV=production
ENV JWT_SECRET=supersecretvalue123
ARG NPM_TOKEN
WORKDIR /app
COPY . .
RUN apt-get update
RUN apt-get install -y curl sudo
RUN curl -fsSL https://deb.example.invalid/setup.sh | bash
RUN npm install
ADD ./start.sh /app/start.sh
RUN chmod 777 /app/start.sh
EXPOSE 22 3000
CMD npm start
