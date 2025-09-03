FROM python:latest 

COPY app.py /app/
COPY project2.sql /app/

WORKDIR /app

RUN pip3 install flask

ENV FLASK_APP=app.py

CMD ["flask", "run", "--host=0.0.0.0"]