FROM ubuntu:16.04
MAINTAINER Mizanul H. Chowdhury
# NOTE: USE __MONGO__ for substituition from docker_build.sh

RUN apt update
RUN apt-get install -y git
RUN apt-get install -y gcc
RUN apt-get install -y g++
RUN apt-get install -y zlib1g-dev
# already loaded via dependencies: libc6, libc6-dev, libpython3.4-dev, libexpat1-dev
RUN apt-get install -y libxml2-dev
RUN apt-get install -y libxslt-dev
RUN apt-get install -y pkg-config
RUN apt-get install -y libxmlsec1-dev

# original stuff for python
RUN apt-get install -y python3
RUN apt-get install -y python3-dev
RUN apt-get install -y wget

RUN wget https://bootstrap.pypa.io/get-pip.py
RUN python3 get-pip.py && pip install -U setuptools && rm get-pip.py
RUN pip3 install --upgrade pip

WORKDIR /tmp
ADD requirements.txt /tmp

RUN pip3 install -r requirements.txt
ADD megan_id_client_library-1.0a1-py3-none-any.whl /tmp

RUN pip3 install megan_id_client_library-1.0a1-py3-none-any.whl

VOLUME ["/opt/server"]
WORKDIR /opt/server
ENV PYTHONPATH $PYTHONPATH:/opt/server:/opt/server/id:/opt/server/id/id_client_sample

WORKDIR /opt/server/id
