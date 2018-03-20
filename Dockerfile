FROM shellphish/mechaphish

COPY --chown=angr:angr . /home/angr/autoPwn/.

RUN . /home/angr/.virtualenvs/angr/bin/activate && \
    pip install -U pip setuptools && \
    cd /home/angr/autoPwn/ && pip install -e . && \
    echo "autoPwn -h" >> ~/.bashrc

RUN ["/bin/bash"]
