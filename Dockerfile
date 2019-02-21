FROM shellphish/mechaphish
#FROM bannsec/mechaphish

COPY --chown=angr:angr . /home/angr/autoPwn/.
USER root
RUN /home/angr/autoPwn/docker_setup.sh

USER angr
RUN ["/bin/bash"]
