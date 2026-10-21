FROM node:20-alpine

# The control centre drives the rig through the Docker socket: SPIRE entries, agent runs. openssl makes the subject
# template for a bridge key's CSR, which the KMS signs (src/vault.js).
RUN apk add --no-cache docker-cli openssl

WORKDIR /app

# Install dependencies first so the layer caches between code changes.
COPY package.json package-lock.json* ./
RUN npm install --omit=dev && npm cache clean --force

COPY src ./src
COPY public ./public
COPY seed ./seed

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]
