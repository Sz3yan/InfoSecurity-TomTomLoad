FROM python:3.10-slim

WORKDIR /identity-proxy

COPY ../requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./identity-proxy

CMD exec gunicorn --bind 0.0.0.0:80 --workers 1 --threads 8 --timeout 0 app:app
