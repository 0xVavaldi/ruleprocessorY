# Build Layer
FROM alpine:latest as build-env
COPY . .
RUN apk add --no-cache build-base cmake && \
    cmake . && make

# Final Layer
FROM alpine:latest
COPY --from=build-env /ruleprocessorY /sbin/ruleprocessorY
RUN apk add --no-cache build-base tini
WORKDIR /data
ENTRYPOINT ["/sbin/tini", "--", "/sbin/ruleprocessorY"]
