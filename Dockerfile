FROM shellphish/mechaphish

# --chown wasn't implemented until Docker 17.09. Dockerhub is still on 17.06.
# Change this back once Dockerhub catches up...
#COPY --chown=angr:angr . /home/angr/autoPwn/.
COPY . /home/angr/autoPwn/.
USER root
RUN chown -R angr:angr /home/angr/autoPwn

USER angr
RUN . /home/angr/.virtualenvs/angr/bin/activate && \
    pip install -U pip setuptools && \
    cd /home/angr/autoPwn/ && pip install -e . && \
    echo "autoPwn -h" >> ~/.bashrc

RUN ["/bin/bash"]
