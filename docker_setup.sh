#!/bin/bash

function remove_workon() {
    echo "Removing base workon"
    sed -i 's/workon angr//g' /home/angr/.bashrc
}

function apt_update () {
    echo "Updating APT"

    # Enable deb-src
    sed -i 's/^\#.*deb-src /deb-src /g' /etc/apt/sources.list

    # Removing GDB here to compile it later..
    apt-get remove -y gdb*
    apt-get update
    apt-get dist-upgrade -y
    apt-get install -y byacc bison flex python2.7-dev texinfo build-essential gcc g++ git libncurses5-dev libmpfr-dev pkg-config libipt-dev libbabeltrace-ctf-dev coreutils g++-multilib libc6-dev-i386 valabind valac swig graphviz xdot net-tools htop netcat ltrace wget curl python python-pip python3 python3-pip libbabeltrace1 libipt1 libc6-dbg

    echo "alias ltrace='ltrace -C -f -n 5 -s 512 -S -i'" >> /home/angr/.bashrc
    echo export PATH=/home/angr/bin:\$PATH >> /home/angr/.bashrc
}

function download_sources () {
    mkdir -p /opt/dbgsrc
    cd /opt/dbgsrc
    apt-get source libc6
    # Clean up the source tar files
    rm -f glibc*
}

function install_cmake () {
    echo "Installing cmake"

    mkdir -p /opt/cmake
    cd /opt/cmake
    CMAKE_URL=`wget -q -O- https://cmake.org/download/ | grep -Po "https://.*?Linux-x86_64.sh" | head -1`
    wget -O cmake.sh $CMAKE_URL
    chmod +x cmake.sh
    yes | ./cmake.sh --skip-license
    rm cmake.sh
    cp -r * /usr/local/.
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
        r2pm update;
        sudo \$(which r2pm) install lang-python;
        sudo \$(which r2pm) install r2api-python;
        pip3 install r2pipe;
        sudo chown -R angr:angr /home/angr/.local/share/radare2;
        r2pm install r2ghidra-dec;
        echo e cmd.pdc=pdg >> ~/.radare2rc
        echo e scr.utf8 = true >> ~/.radare2rc
        echo e scr.utf8.curvy = true >> ~/.radare2rc
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
        virtualenv --python=$(which python3) /home/angr/.virtualenvs/pwntools;
        . /home/angr/.virtualenvs/pwntools/bin/activate;
        pip install https://github.com/Gallopsled/pwntools/archive/dev3.zip
    " angr
}

function install_ghidra () {
    
    su -c "
        cd /opt/ghidra* && echo export PATH=\\\$PATH:\$PWD:\$PWD/server:\$PWD/support >> /home/angr/.bashrc && \
        cd /opt/jdk*/bin && echo export PATH=\$PWD:\\\$PATH >> /home/angr/.bashrc
    " angr

}

function fixup_ipython () {
    # Move ipython into virtualenvs instead of outside

    su -c "
        pip uninstall -y ipython;
        . /home/angr/.virtualenvs/angr/bin/activate;
        pip install ipython
    " angr
}

function install_angr_targets () {
    # TODO: Remove this once angr_targets is in the default angr dev pull

    su -c "
        mkdir -p ~/opt;
        cd ~/opt;
        . /home/angr/.virtualenvs/angr/bin/activate;
        git clone https://github.com/angr/angr-targets.git;
        cd angr-targets;
        pip install -e .;
        
    " angr
}

function install_frida () {
    # TODO: Installing this gobally for now, since i want to be able to use it from anywhere.
    pip3 install frida frida-tools
}

#
#
#

remove_workon
apt_update
download_sources

# These are in separate build stages now
#build_install_gdb
#install_radamsa

install_cmake
setup_patchkit
install_autopwn
install_r2
install_libdislocator
update_shellphish_afl
install_seccomp_filter
install_py3pwntools
install_angr_targets
install_frida
fixup_ipython

# Make sure this is the last thing we do in bashrc
echo workon angr >> /home/angr/.bashrc
echo "autoPwn -h" >> /home/angr/.bashrc;
echo "autoPwnCompile -h" >> /home/angr/.bashrc;

# Workon is fucking up my PATH for some reason.. Doing this after.
install_ghidra
