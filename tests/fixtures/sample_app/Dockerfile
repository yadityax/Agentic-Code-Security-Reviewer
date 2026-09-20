FROM python:latest
ADD . /app
WORKDIR /app
ENV DB_PASSWORD=hunter2hunter2
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
