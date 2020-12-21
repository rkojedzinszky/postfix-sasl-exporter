FROM scratch

LABEL org.opencontainers.image.authors "Richard Kojedzinszky <richard@kojedz.in>"
LABEL org.opencontainers.image.source https://github.com/rkojedzinszky/postfix-sasl-exporter

COPY postfix-sasl-exporter /

USER 20562

CMD ["/postfix-sasl-exporter"]
