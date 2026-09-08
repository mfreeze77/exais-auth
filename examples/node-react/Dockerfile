FROM node@sha256:d649c27dae7ba0137b3cef5dd75baa422c08dc3d9e3fc0c23dfb172dc3cc6436
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY server.js client.jsx build.mjs ./
COPY public ./public
RUN npm run build
ENV NODE_ENV=production
USER node
EXPOSE 3000
CMD ["node", "server.js"]
