To execute the binary, please retrieve it at http://nightmared.fr/files/binary-sgx-demo.tar:
```
wget http://nightmared.fr/files/binary-sgx-demo.tar
docker run --rm -it -v /home/nightmared/dev/tlssec/projet-long/incubator-teaclave-sgx-sdk/samplecode/spectre/bin:/work --device=/dev/sgx/enclave:/dev/sgx/enclave:rw --device=/dev/sgx/provision:/dev/sgx/provision:rw ubuntu /bin/bash
```

Inside the container, run the following commands:
```
cd /work
tar xvf binary-sgx-demo.tar
LD_LIBRARY_PATH=libs ./libs/ld-linux-x86-64.so.2 ./app
```

That's it, enjoy!
