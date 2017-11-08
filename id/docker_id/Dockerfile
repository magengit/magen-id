FROM magendocker/magen-core:latest
MAINTAINER Alena Lifar

ADD server.* /etc/ssl/certs/

VOLUME ["/opt/server"]
WORKDIR /opt/server
ENV PYTHONPATH $PYTHONPATH:/opt/server:/opt/server/id_service:/opt/server/id_service

RUN rm -rf __pycache__/
RUN rm -rf tests/__pycache__/

WORKDIR /opt/server/id

RUN rm -rf __pycache__/
RUN rm -rf tests/__pycache__/

# For dev:
WORKDIR /tmp
COPY magen*.whl /tmp
RUN pip3 install magen*.whl

WORKDIR /opt/server/id
