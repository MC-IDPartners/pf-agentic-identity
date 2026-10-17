# PingAuthorize, the rig's policy decision point (vendored from idp-agentic-demo/pingauthorize/Dockerfile.railway):
# the embedded PDP with a static deployment package, and the AuthZEN servlet extension in front of it, so the PEP
# (coaz-pep) asks it AuthZEN evaluations at http://pingauthorize:1080/access/v1/evaluation.
#
# Licence: the stock start-up hook fetches a DevOps evaluation licence from PING_IDENTITY_DEVOPS_USER/KEY (the
# rig's ~/.pingidentity/config, as PingFederate's), so none is baked in. Version: must match the PAP that exported
# the package (11.1) - an older server refuses a newer package.
FROM pingidentity/pingauthorize:11.1.0.0-latest

ENV PING_IDENTITY_ACCEPT_EULA=YES
ENV MAX_HEAP_SIZE=1g

COPY --chown=9031:0 pd.profile /opt/in/pd.profile
# The policy: rig.deploymentpackage, authored in the PAP (pingauthorize-pap) through its API and exported by
# author-policy.py - digest-sealed, so it is regenerated there, never edited by hand.
COPY --chown=9031:0 rig.deploymentpackage /opt/in/rig.deploymentpackage

# The AuthZEN servlet, installed into the product bits (installing it through the server profile fails on 11.1:
# setup aborts with "Server Already Configured"). The whole tree is chowned after: the start-up hooks copy it as
# uid 9031.
USER root
COPY --chown=9031:0 extension/authzen-adapter-1.0.0.zip /tmp/authzen-adapter.zip
RUN /opt/server/bin/manage-extension --install /tmp/authzen-adapter.zip --no-prompt --ignoreWarnings \
    && rm -f /tmp/authzen-adapter.zip \
    && chown -R 9031:0 /opt/server
USER 9031:0

EXPOSE 1443 1080
CMD ["start-server"]
