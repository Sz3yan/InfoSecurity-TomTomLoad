FROM python:3.10-slim

WORKDIR /identity-proxy

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./identity-proxy

# for API (fastapi)
#CMD exec uvicorn app:app --host 0.0.0.0 --port 80

CMD exec gunicorn --bind 0.0.0.0:80 --workers 1 --threads 8 --timeout 0 app:app

# gcloud builds submit --tag gcr.io/sz3yan-357410/index
# gcloud run deploy --image  gcr.io/sz3yan-357410/index --platform managed
