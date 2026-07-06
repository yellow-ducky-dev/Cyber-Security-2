# ─── BUILD STAGE ──────────────────────────────────────────────────────
FROM node:18-alpine AS builder

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm ci --only=production

# ─── PRODUCTION STAGE ──────────────────────────────────────────────────
FROM node:18-alpine

ENV NODE_ENV=production
WORKDIR /usr/src/app

# Copy production node_modules and package file
COPY --from=builder /usr/src/app/node_modules ./node_modules
COPY --from=builder /usr/src/app/package*.json ./

# Copy application files
COPY . .

# Ensure logs subdirectory is writeable by the node user
RUN mkdir -p logs && chown -R node:node /usr/src/app

# Run container as a non-privileged system user "node" (Zero Trust Principle)
USER node

EXPOSE 8080

CMD ["node", "server.js"]
