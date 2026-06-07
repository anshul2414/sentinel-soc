FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /data
ENV DB_PATH=/data/sentinel.db PYTHONUNBUFFERED=1
EXPOSE 5000
CMD ["gunicorn","--worker-class","eventlet","-w","1","--bind","0.0.0.0:5000","--timeout","120","app:app"]
