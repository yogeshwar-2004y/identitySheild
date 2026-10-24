# Build context: repository root (needs infra/nginx).
FROM node:22-alpine AS build
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY frontend/ ./
RUN npm run build

FROM nginx:1.27-alpine
COPY infra/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build /web/dist /usr/share/nginx/html
EXPOSE 80
