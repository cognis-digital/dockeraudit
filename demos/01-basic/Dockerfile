# Realistic "before" Dockerfile with several hygiene smells.
FROM python:latest

ENV API_KEY=sk_live_5fbe22a1c0d94e2f8a7b
ARG DB_PASSWORD=hunter2

RUN apt-get update && apt-get install -y curl build-essential
RUN curl -fsSL https://example.com/install.sh | sudo bash
RUN chmod -R 777 /app

ADD ./requirements.txt /app/requirements.txt
COPY . /app

WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 22
EXPOSE 8000

CMD ["python", "server.py"]
