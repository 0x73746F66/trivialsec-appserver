FROM registry.gitlab.com/trivialsec/containers-common/python
LABEL org.opencontainers.image.authors="Christopher Langton"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://gitlab.com/trivialsec/appserver"

ARG COMMON_VERSION
ARG AWS_REGION
ARG AWS_DEFAULT_REGION
ARG AWS_ACCESS_KEY_ID
ARG AWS_SECRET_ACCESS_KEY
ARG BUILD_ENV

ENV PYTHONPATH /srv/app
ENV APP_ENV ${APP_ENV}
ENV APP_NAME ${APP_NAME}
ENV AWS_REGION ${AWS_REGION}
ENV AWS_DEFAULT_REGION ${AWS_DEFAULT_REGION}
ENV AWS_ACCESS_KEY_ID ${AWS_ACCESS_KEY_ID}
ENV AWS_SECRET_ACCESS_KEY ${AWS_SECRET_ACCESS_KEY}
ENV CONFIG_FILE ${CONFIG_FILE}
ENV FLASK_RUN_PORT ${FLASK_RUN_PORT}
ENV FLASK_DEBUG ${FLASK_DEBUG}
ENV FLASK_ENV ${FLASK_ENV}

COPY --chown=trivialsec:trivialsec src .
COPY --chown=trivialsec:trivialsec conf/app-${BUILD_ENV}.ini .
COPY --chown=trivialsec:trivialsec requirements.txt .
RUN echo "Test AWS Credentials stored in Env vars" && \
    aws sts get-caller-identity && \
    echo "Downloading Packages from S3" && \
    aws s3 cp --only-show-errors s3://static-trivialsec/deploy-packages/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl \
        /srv/app/trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl && \
    aws s3 cp --only-show-errors s3://static-trivialsec/deploy-packages/${COMMON_VERSION}/build.tgz /tmp/trivialsec/build.tgz && \
    echo "Installing Packages" && \
    tar -xzvf /tmp/trivialsec/build.tgz -C /srv/app && \
    python3 -m pip install -q --user --no-cache-dir --find-links=/srv/app/build/wheel --no-index trivialsec_common-${COMMON_VERSION}-py2.py3-none-any.whl && \
    python3 -m pip install -q -U --user --no-cache-dir --isolated -r requirements.txt && \
    echo "Clean up..." && \
        rm -rf /tmp/trivialsec

CMD ["uuwsgi", "--", "app.ini"]
