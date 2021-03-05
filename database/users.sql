CREATE DATABASE users WITH ENCODING = 'UTF8' OWNER = postgre;
 \connect users;

-- Создаем отдельную схему для нашего контента
CREATE SCHEMA IF NOT EXISTS content;
