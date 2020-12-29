FROM python:3.8-slim
WORKDIR /app
ADD requirements.txt .
RUN python3 -m pip install -r requirements.txt
ADD . .
ENTRYPOINT [ "gunicorn", "-b", "0.0.0.0:8000", "-w", "2", "app:app" ]