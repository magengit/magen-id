PACKAGE_TAG = id
PACKAGE_NAME = magen_$(PACKAGE_TAG)_service
WHEEL := $(PACKAGE_NAME)-1.0a2-py3-none-any.whl
SPHINX_DIR=./docs
DOCKER_SRC_TAG=magen_id:v1.0
DOCKER_IMAGE=magen-id
DOCKER_DIR=docker_$(PACKAGE_TAG)
PYTHON=python3
MAKE=make
PYTEST=pytest
COVERAGE=coverage run -m
SERVER_PID=
BUILDDIR=_build
OS := $(shell uname)
SERVER_NAME=id_server.py

MAGEN_HELPER=../lib/magen_helper

ID_SERVER_WRAPPER=bash id_scripts/id_server_wrapper.sh

include $(MAGEN_HELPER)/make_common/docker_common.mk
include $(MAGEN_HELPER)/make_common/package_common.mk
include $(MAGEN_HELPER)/make_common/doc_common.mk

default: common_default

update: common_update

clean_docker: common_clean_docker

stop_docker: common_stop_docker

rm_docker: common_rm_docker

all: common_all

clean: common_clean

package: common_package

install: common_install

upload: common_upload

SPHINX_API_ID_SERVER_OMITS=id_service/magen_env.py
SPHINX_API_ID_APIS_OMITS=

doc_api:
	$(SPHINX_APIDOC) -o $(SPHINX_DIR) --force id_service/magenid/idsapp/idsserver/rest $(SPHINX_API_ID_SERVER_OMITS)
	$(SPHINX_APIDOC) -o $(SPHINX_DIR) --force id_service/magenid/idsapp/idsserver/lib/bll $(SPHINX_API_ID_APIS_OMITS)

# core of "make doc"
doc_build: doc_api common_doc

doc:
	@$(MAKE) doc_build

doc_clean:
	make -C docs clean

uninstall: common_uninstall

list: common_list

pre_test: ;
coverage_report: ;

run_unit_test:
	@sleep 2
	$(info ************  STARTING TESTS ************)
	@$(ID_SERVER_WRAPPER) -mode test

test: common_test

# see test: for documentation
test_travis: common_test_travis

check: common_check

build_docker:  common_build_docker

test_docker_travis: common_test_docker

test_docker: test_docker_travis 

run_docker: common_run_docker

runpkg_docker: common_runpkg_docker

run: common_run

.PHONY:  pre_test coverage_report all build_docker
