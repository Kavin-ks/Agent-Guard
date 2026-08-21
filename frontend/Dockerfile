# Agent Guard frontend + reverse proxy.
# Stage 1: build the static dashboard. Stage 2: nginx serves it AND proxies /api
# to the backend, injecting the X-API-Key header server-side (never in the bundle).

FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
# Static assets.
COPY --from=build /app/dist /usr/share/nginx/html
# Config template — nginx's entrypoint runs envsubst on *.template, substituting
# only the env vars we define (AGENTGUARD_API_KEY, BACKEND_URL); $host/$uri etc.
# are left intact because they are not in the environment.
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

EXPOSE 80
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
    CMD wget -qO- http://localhost/api/health >/dev/null 2>&1 || exit 1
