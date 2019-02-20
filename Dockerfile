FROM shellphish/mechaphish
#FROM bannsec/mechaphish

# --chown wasn't implemented until Docker 17.09. Dockerhub is still on 17.06.
# Change this back once Dockerhub catches up...
#COPY --chown=angr:angr . /home/angr/autoPwn/.
COPY . /home/angr/autoPwn/.
USER root
RUN chown -R angr:angr /home/angr/autoPwn && \
    apt-get remove -y gdb*  && apt-get update -y && apt-get install -y byacc bison flex python2.7-dev texinfo build-essential gcc g++ git  libncurses5-dev libmpfr-dev pkg-config libipt-dev libbabeltrace-ctf-dev coreutils gdb-multiarch g++-multilib libc6-dev-i386 && \
    mkdir -p /opt && cd /opt && git clone --depth 1 git://sourceware.org/git/binutils-gdb.git && cd binutils-gdb && \
    ./configure --with-python=python3 && make -j`nproc` && make install && \
    cd /opt && git clone https://gitlab.com/akihe/radamsa.git && cd radamsa && make -j`nproc` && make install

USER angr
RUN virtualenv --python=$(which python2) /home/angr/.virtualenvs/patchkit && . /home/angr/.virtualenvs/patchkit/bin/activate && pip install -U setuptools && pip install capstone keystone-engine && find ~/.virtualenvs/angr -name "libkeystone.so" -exec ln -s {} /home/angr/.virtualenvs/patchkit/lib/python2.7/site-packages/keystone/libkeystone.so \; && \
    . /home/angr/.virtualenvs/angr/bin/activate && \
    pip install -U pip setuptools && \
    cd /home/angr/autoPwn/ && pip install -e . && \
    echo "autoPwn -h" >> ~/.bashrc && \
    echo "autoPwnCompile -h" >> ~/.bashrc && \
    cp /home/angr/autoPwn/gdbinit /home/angr/.gdbinit && \
    pip install angrgdb bintrees && \
    cd /home/angr && git clone --depth 1 --single-branch --branch docker-with-pie https://github.com/bannsec/patchkit.git && \
    mkdir -p ~/opt && cd ~/opt && wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz && tar xf afl-latest.tgz && rm afl-latest.tgz && cd afl*/libdislocator && CC="gcc -m32" make && mv libdislocator.so libdislocator32.so && make && mv libdislocator.so libdislocator64.so && echo alias DISLOCATOR32="LD_PRELOAD=$PWD/libdislocator32.so" >> ~/.bashrc && echo alias DISLOCATOR64="LD_PRELOAD=$PWD/libdislocator64.so" >> ~/.bashrc

RUN ["/bin/bash"]
