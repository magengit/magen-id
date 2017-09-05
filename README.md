# Magen ID Service

[![Build Status](https://travis-ci.org/magengit/magen-id.svg?branch=master)](https://travis-ci.org/magengit/magen-id)

Magen ID Service is a microservice responsible for authentication and authorization for users to access resources. It exposes REST API
for managing client, user, group and token authorization.

Supported key formats: JSON, JWT

Current version: ```1.3a1```

For This Service there are available ```make``` commands. Makefile is located under [**id/**](id)

Make Default Target: ```make default```. Here is the list of targets available for ID service

```make
default:
        @echo 'Makefile for Magen ID Service'
        @echo
        @echo 'Usage:'
        @echo ' make clean              :Remove packages from system and pyc files'
        @echo ' make test               :Run the test suite'
        @echo ' make package            :Create Python wheel package'
        @echo ' make install            :Install Python wheel package'
        @echo ' make all                :clean->package->install'
        @echo ' make list               :List of All Magen Dependencies'
        @echo ' make build_docker       :Pull Base Docker Image and Current Image'
        @echo ' make run_docker         :Build and Run required Docker containers with mounted source'
        @echo ' make runpkg_docker      :Build and Run required Docker containers with created wheel'
        @echo ' make test_docker        :Build, Start and Run tests inside main Docker container interactively'
        @echo ' make stop_docker        :Stop and Remove All running Docker containers'
        @echo ' make clean_docker       :Remove Docker unused images'
        @echo ' make rm_docker          :Remove All Docker images if no containers running'
        @echo ' make doc                :Generate Sphinx API docs'
        @echo
        @echo
```

## Requirements: MacOS X
0. ```python3 -V```: Python **3.5.2** (>=**3.4**)
0. ```pip3 -V```: pip **9.0.1**
0. ```make -v```: GNU Make **3.81**
1. ```docker -v```: Docker version **17.03.0-ce**, build 60ccb22
2. ```docker-compose -v```: docker-compose version **1.11.2**, build dfed245
3. Make sure you have correct rights to clone Cisco-Magen github organization

## Requirements: AWS EC2 Ubuntu
0. ```python3 -V```: Python **3.5.2**
1. ```pip3 -V```: pip **9.0.1**
2. ```make -v```: GNU Make **4.1**
3. ```docker -v```: Docker version **17.03.0-ce**, build 60ccb22
4. ```docker-compose -v```: docker-compose version **1.11.2**, build dfed245
5. Make sure AWS user and **root** have correct rights to Cisco-Magen github organization

## Targets

1. ```make all```  -> Install *Magen-Core* dependencies, clean, package and install **ks** package
2. ```make test``` -> run **id** tests

## Adopt this Infrastructure

1. get [**helper_scripts**](id/helper_scripts) to the repo
2. follow the structure in [**docker_ks**](id/docker_ks) to create ```docker-compose.yml``` and ```Dockerfile``` files
3. use [**Makefile**](id/Makefile) as an example for building make automation

## Sphinx Documentation SetUp

There is a configured Sphinx API docs for the service. 
To compile docs execute: 

```make html``` in [```docs```](id/docs) directory
    
or run:

```make doc``` in the [```ingestion```](id) directory


#ID SERVICE

- id/id_service/data/bootstrap.json contains the initial data that you need to run id service.
- id/id_service/magenid/idsapp/settings.py contains the Issuer url, etc.

##To Run The ID Serivce

1. Open the bootstrap.json file with your preferred text editor
2. Add/Remove the User and Group info
3. Add/Remove items in the connected_apps. A sample connected app has been added. It can be used for running your "id_client_sample". If you change the host/port of the "id_client_sample" then you need to update the url under "redirect_uris". Also, make sure the "id_client_sample" uses the same "client_id", "client_secret". 

4. Open a Terminal. Navigate to the "id" directory, and run the following command:

```bash
$ make run_docker

```

#ID CLIENT SAMPLE

- id_client_sample/settings.py file contains the id service host url, callbak url, username, etc. Make sure you edit this before your start the client app.

## To Run The ID CLIENT SAMPLE

4. Open a Terminal. Navigate to the "id/id_client_sample_docker" directory, and run the following command:

```bash
$ docker-compose up

```

