# Imagem do alvo vulnerável, para rodar isolado (recomendado para scan ativo
# do ZAP, que envia payloads de command injection para /admin/exec).
FROM node:22-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY . .
ENV HOST=0.0.0.0 PORT=3000
USER node
EXPOSE 3000
CMD ["node", "server.js"]
