FROM shellphish/mechaphish
#FROM bannsec/mechaphish

COPY --chown=angr:angr . /home/angr/autoPwn/.

USER root
RUN /home/angr/autoPwn/docker_setup.sh

COPY --from=bannsec/autopwn-stage-gdb /opt/gdb/. /usr/.

USER angr
RUN ["/bin/bash"]
