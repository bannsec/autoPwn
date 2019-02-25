FROM shellphish/mechaphish
#FROM bannsec/mechaphish

COPY --chown=angr:angr . /home/angr/autoPwn/.

USER root
RUN /home/angr/autoPwn/docker_setup.sh

COPY --from=bannsec/autopwn-stage-gdb /opt/gdb/. /usr/.
COPY --from=bannsec/autopwn-stage-radamsa /opt/radamsa_install/. /.

USER angr
RUN ["/bin/bash"]
