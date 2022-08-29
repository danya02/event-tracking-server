FROM python:3.9

ENV PYTHONUNBUFFERED yes

ADD requirements.txt /
RUN pip install -r requirements.txt

COPY static/ /static
COPY templates/ /templates
COPY database.py /
COPY main.py /

ENTRYPOINT ["gunicorn", "main:app", "-w", "2", "--threads", "2", "-b 0.0.0.0:8000", "-R"]
