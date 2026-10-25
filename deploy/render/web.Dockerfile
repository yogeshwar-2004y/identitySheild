# Dashboard for Render: same SPA build as frontend/Dockerfile, nginx config rendered from env
# (PORT, API_HOST, KEYCLOAK_PUBLIC_URL) by the nginx image's template step at start-up.
FROM node:22-alpine AS build
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY frontend/ ./
RUN npm run build

FROM nginx:1.27-alpine
RUN rm /etc/nginx/conf.d/default.conf
COPY deploy/render/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --chmod=755 deploy/render/nginx-hosts.envsh /docker-entrypoint.d/14-render-hosts.envsh
COPY --chmod=755 deploy/render/nginx-resolver.sh /docker-entrypoint.d/15-resolver.sh
COPY --from=build /web/dist /usr/share/nginx/html
ENV PORT=8080
