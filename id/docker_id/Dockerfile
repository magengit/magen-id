FROM magendocker/magen-core:latest
MAINTAINER Mizanul H. Chowdhury

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
COPY magen_id_service-1.0a2-py3-none-any.whl /tmp
RUN pip3 install magen_id_service-1.0a2-py3-none-any.whl

WORKDIR /opt/server/id
