FROM shellphish/mechaphish
#FROM bannsec/mechaphish

USER root

COPY --from=bannsec/autopwn-stage-gdb /opt/gdb/. /usr/.
COPY --from=bannsec/autopwn-stage-radamsa /opt/radamsa_install/. /.
COPY --from=bannsec/autopwn-stage-ghidra /opt/. /opt/.
COPY --chown=angr:angr . /home/angr/autoPwn/.

RUN /home/angr/autoPwn/docker_setup.sh

USER angr
RUN ["/bin/bash"]
