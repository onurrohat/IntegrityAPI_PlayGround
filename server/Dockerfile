# Play Integrity verification server - Cloud Run image.
FROM node:22-slim

WORKDIR /app

# Copy only the manifests first and install dependencies (for layer caching).
COPY package*.json ./
RUN npm ci --omit=dev

# Application source.
COPY . .

# Cloud Run injects the PORT env var; server.js already reads process.env.PORT.
ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "server.js"]
