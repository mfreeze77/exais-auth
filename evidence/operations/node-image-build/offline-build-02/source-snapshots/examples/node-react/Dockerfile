FROM node@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436
WORKDIR /app
COPY package.json package-lock.json ./
RUN --network=none --mount=type=bind,from=node_packages,target=/npm-cache,rw \
    npm ci --offline --cache=/npm-cache --ignore-scripts --no-audit --no-fund
COPY server.js email-delivery.js client.jsx build.mjs ./
COPY public ./public
RUN --network=none node build.mjs
ENV NODE_ENV=production
USER node
EXPOSE 3000
CMD ["node", "server.js"]
