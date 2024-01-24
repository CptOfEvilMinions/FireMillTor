FROM alpine:latest

# Install TOR
RUN apk update && apk add tor

# Set tor's UID
# TOR package creates TOR user
#RUN addgroup -S tor && adduser -S -G tor tor

# Copy TOR config
COPY conf/tor/torrc /etc/tor/torrc

# make sure files are owned by tor user
RUN chown tor -R /etc/tor
RUN chown tor -R /var/log/tor

USER tor

# default port to used for incoming Tor connections
# can be changed by changing 'ORPort' in torrc
EXPOSE 9001
CMD ["tor","-f","/etc/tor/torrc"]
