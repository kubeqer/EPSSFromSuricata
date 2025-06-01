FROM node:23-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

ARG REACT_APP_API_URL


ENV REACT_APP_API_URL=$REACT_APP_API_URL

RUN npm run build

FROM node:23-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/build ./build

RUN npm install -g serve

CMD ["npx", "serve", "-s", "build"]
