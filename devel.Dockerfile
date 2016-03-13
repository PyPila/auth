FROM python:3.5

MAINTAINER Pawel Kucmus <pkucmus@gmail.com>

ADD requirements requirements
RUN pip install -U pip
RUN pip install -r requirements/devel.txt --process-dependency-links

ENV DJANGO_SETTINGS_MODULE=service.settings.local

ADD src /run/service
WORKDIR /run/service

ADD auth-client /run/auth-client
RUN pip install -e ../auth-client --process-dependency-links

EXPOSE 8000

ENTRYPOINT ["python", "manage.py"]
CMD ["runserver", "0.0.0.0:8000"]
