ARG DOCKER_REGISTRY
FROM ${DOCKER_REGISTRY}/debian:latest

ARG GIT_BRANCH
ARG GIT_COMMIT
ARG GIT_URL
ARG JENKINS_JOB_NAME
ARG JENKINS_URL

LABEL com.whitehat.git.branch=${GIT_BRANCH} \
    com.whitehat.git.commit=${GIT_COMMIT} \
    com.whitehat.git.url=${GIT_URL} \
    com.whitehat.jenkins.jobname=${JENKINS_JOB_NAME} \
    com.whitehat.jenkins.url=${JENKINS_URL}

COPY bin/auth-example-linux-amd64 /bin/auth-example

ENTRYPOINT ["/bin/auth-example"]