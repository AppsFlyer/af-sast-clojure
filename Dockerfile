FROM clojure:openjdk-8-tools-deps AS builder
WORKDIR /src

COPY . .
RUN clojure -M:uberjar

# we will use openjdk 8 with alpine as it is a very small linux distro
FROM openjdk:8-jre-alpine3.9

# copy the packaged jar file into our docker image
COPY --from=builder /src/target/clj-scanner.jar /clj-scanner.jar

COPY entry-point.sh /bin
RUN chmod +x /bin/entry-point.sh

CMD []
ENTRYPOINT ["/bin/entry-point.sh"]
