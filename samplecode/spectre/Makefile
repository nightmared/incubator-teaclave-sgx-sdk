# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

######## SGX SDK Settings ########

SGX_SDK ?= /opt/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

TOP_DIR := ../..
include $(TOP_DIR)/buildenv.mk

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

SGX_COMMON_CFLAGS += -fstack-protector

######## CUSTOM Settings ########

CUSTOM_LIBRARY_PATH := ./lib
CUSTOM_BIN_PATH := ./bin
CUSTOM_EDL_PATH := ../../edl
CUSTOM_COMMON_PATH := ../../common

######## EDL Settings ########

Enclave_EDL_Files := enclave1/Enclave1_t.c enclave1/Enclave1_t.h app/Enclave_u.c app/Enclave_u.h

######## APP Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Rust_Flags := --release
App_SRC_Files := $(shell find app/ -type f -name '*.rs') $(shell find app/ -type f -name 'Cargo.toml')
App_Include_Paths := -I ./app -I./include -I$(SGX_SDK)/include -I$(CUSTOM_EDL_PATH)
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

App_Rust_Path := ./app/target/release
App_Enclave1_u_Object :=lib/libEnclave_u.a
App_Name := bin/app

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto
KeyExchange_Library_Name := sgx_tkey_exchange
ProtectedFs_Library_Name := sgx_tprotected_fs

RustEnclave_C_Files := $(wildcard ./enclave1/*.c ./attestation/*.c)
RustEnclave_C_Objects := $(RustEnclave_C_Files:.c=.o)
RustEnclave_Include_Paths := -I$(CUSTOM_COMMON_PATH)/inc -I$(CUSTOM_EDL_PATH) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid

RustEnclave_Link_Libs := -L$(CUSTOM_LIBRARY_PATH)
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) $(ENCLAVE_CFLAGS) $(RustEnclave_Include_Paths)
RustEnclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -l$(Crypto_Library_Name) -l$(Service_Library_Name) $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,--version-script=enclave1/Enclave1.lds \
	$(ENCLAVE_LDFLAGS)

RustEnclave1_Name := enclave1/enclave1.so

Signed_RustEnclave1_Name := bin/enclave1.signed.so

.PHONY: all
all: $(Enclave_EDL_Files) $(App_Name) $(Signed_RustEnclave1_Name)

######## EDL Objects ########

$(Enclave_EDL_Files): $(SGX_EDGER8R) enclave1/Enclave1.edl
	$(SGX_EDGER8R) --use-prefix --trusted enclave1/Enclave1.edl --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --trusted-dir enclave1
	$(SGX_EDGER8R) --use-prefix --untrusted enclave1/Enclave1.edl --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --untrusted-dir app

	@echo "GEN  =>  $(Enclave_EDL_Files)"

######## App Objects ########

app/Enclave1_u.o: $(Enclave_EDL_Files)
	@$(CC) $(App_C_Flags) -c app/Enclave1_u.c -o $@
	@echo "CC   <=  $<"

$(App_Enclave1_u_Object): app/Enclave1_u.o
	$(AR) rcsD $@ $^

$(App_Name): $(App_Enclave1_u_Object) $(App_SRC_Files)
	@cd app && SGX_SDK=$(SGX_SDK) cargo build $(App_Rust_Flags)
	@echo "Cargo  =>  $@"
	mkdir -p bin
	cp $(App_Rust_Path)/app ./bin

######## Enclave Objects ########

##### Enclave 1 ###########

enclave1/Enclave1_t.o: enclave1/Enclave1_t.c
	@$(CC) $(RustEnclave_Compile_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(RustEnclave1_Name): enclave1 enclave1/Enclave1_t.o
	@$(CXX) enclave1/Enclave1_t.o -o $@ -lenclave1 $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_RustEnclave1_Name): $(RustEnclave1_Name)
	mkdir -p bin
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave1/Enclave1_private.pem -enclave $(RustEnclave1_Name) -out $@ -config enclave1/Enclave1.config.xml
	@echo "SIGN =>  $@"


.PHONY: enclave1
enclave1:
	$(MAKE) -C ./enclave1/

.PHONY: sgx_ustdc
sgx_ustdc:
	$(MAKE) -C ../../sgx_ustdc/ 2> /dev/null

.PHONY: clean
clean:
	@rm -f $(App_Name) $(RustEnclave1_Name) $(Signed_RustEnclave1_Name) $(RustEnclave2_Name) $(Signed_RustEnclave2_Name) $(RustEnclave3_Name) $(Signed_RustEnclave3_Name) $(RustEnclave_C_Objects) $(App_Cpp_Objects) enclave1/*_t.* app/*_u.* lib/*.a
	@cd enclave1 && cargo clean && rm -f Cargo.lock
	@cd app && cargo clean && rm -f Cargo.lock
