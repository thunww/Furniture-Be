FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

# Copy toàn bộ project
COPY . .

# Expose port
EXPOSE 5000

# Chạy file server.js trong thư mục src
CMD ["node", "src/server.js"]
