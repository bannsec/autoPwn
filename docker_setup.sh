#!/bin/bash

function apt_update () {
    echo "Updating APT"

    # Removing GDB here to compile it later..
    apt-get remove -y gdb*
    apt-get update -y
    apt-get install -y byacc bison flex python2.7-dev texinfo build-essential gcc g++ git libncurses5-dev libmpfr-dev pkg-config libipt-dev libbabeltrace-ctf-dev coreutils g++-multilib libc6-dev-i386 valabind valac swig graphviz xdot net-tools htop netcat ltrace

    echo "alias ltrace='ltrace -C -f -n 5 -s 512 -S -i'" >> /home/angr/.bashrc
}

function build_install_gdb () {
    echo "Building and installing gdb"

    mkdir -p /opt
    cd /opt
    git clone --depth 1 git://sourceware.org/git/binutils-gdb.git
    cd binutils-gdb
    ./configure --with-python=python3
    make -j`nproc`
    make install
    cd /opt
    rm -rf binutils-gdb
}

function install_radamsa () {
    echo "Building and installing radamsa"

    cd /opt
    git clone https://gitlab.com/akihe/radamsa.git
    cd radamsa
    make -j`nproc`
    make install
}


function setup_patchkit () {
    echo "Setting up patchkit"

    su -c " 
        virtualenv --python=$(which python2) /home/angr/.virtualenvs/patchkit;
        . /home/angr/.virtualenvs/patchkit/bin/activate;
        pip install -U setuptools;
        pip install capstone keystone-engine;
        find ~/.virtualenvs/angr -name \"libkeystone.so\" -exec ln -s {} /home/angr/.virtualenvs/patchkit/lib/python2.7/site-packages/keystone/libkeystone.so \; ;
        cd /home/angr && git clone --depth 1 --single-branch --branch docker-with-pie https://github.com/bannsec/patchkit.git;
    " angr
}

function install_autopwn () {

    # Futures causes issues with gdb import
    su -c "
        . /home/angr/.virtualenvs/angr/bin/activate && pip uninstall -y futures;
        pip install -U pip setuptools;
        cd /home/angr/autoPwn/ && pip install -e .;
        echo \"autoPwn -h\" >> ~/.bashrc;
        echo \"autoPwnCompile -h\" >> ~/.bashrc;
        cp /home/angr/autoPwn/gdbinit /home/angr/.gdbinit;

        # Install r2dbg fun stuff
        pip install https://github.com/andreafioraldi/angrgdb/archive/master.zip https://github.com/andreafioraldi/angrdbg/archive/master.zip bintrees https://github.com/andreafioraldi/r2angrdbg/archive/master.zip;
    " angr
}

function install_r2 () {

    su -c "
        pip3 install --user r2pipe;
        . /home/angr/.virtualenvs/angr/bin/activate;
        mkdir -p ~/opt;
        cd /home/angr/opt;
        git clone --depth 1 https://github.com/radare/radare2.git;
        cd radare2;
        ./sys/user.sh;
        echo \"export PATH=\\\$PATH:\\\$HOME/bin\" >> ~/.bashrc;
        export PATH=\$PATH:\$HOME/bin;
        r2pm init;
        r2pm install lang-python3;
        sudo \$(which r2pm) install r2api-python;
        pip3 install r2pipe;
    " angr
}

function install_libdislocator () {

    su -c "
        cd ~/opt;
        wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz;
        tar xf afl-latest.tgz;
        rm afl-latest.tgz;
        cd afl*/libdislocator;
        CC=\"gcc -m32\" make;
        mv libdislocator.so libdislocator32.so;
        make;
        mv libdislocator.so libdislocator64.so;
        echo alias DISLOCATOR32=\"LD_PRELOAD=\$PWD/libdislocator32.so\" >> ~/.bashrc;
        echo alias DISLOCATOR64=\"LD_PRELOAD=\$PWD/libdislocator64.so\" >> ~/.bashrc;
    " angr
}

function update_shellphish_afl () {
    # TODO :Remove this once pypi version of shellphish-afl is on 2.52b

    su -c "
        cd ~/opt;
        wget -O shellphish_afl-1.2.1-py3-none-any.whl \"https://github.com/bannsec/autoPwn-tmp/blob/master/shellphish_afl-1.2.1-py3-none-any.whl?raw=true\";
        . /home/angr/.virtualenvs/angr/bin/activate;
        pip install -U shellphish_afl-1.2.1-py3-none-any.whl;
    " angr
}

function install_seccomp_filter () {
    apt-get install -y gcc ruby-dev
    gem install seccomp-tools

    # Yeah, installing one_gadget at the same time
    gem install one_gadget
}

function install_py3pwntools () {

    su -c "
        . /home/angr/.virtualenvs/angr/bin/activate;
        pip install https://github.com/Gallopsled/pwntools/archive/dev3.zip
    " angr
}

#
#
#

apt_update

# These are in separate build stages now
#build_install_gdb
#install_radamsa

setup_patchkit
install_autopwn
install_r2
install_libdislocator
update_shellphish_afl
install_seccomp_filter
install_py3pwntools
