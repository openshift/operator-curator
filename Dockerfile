FROM registry.access.redhat.com/ubi8/ubi-minimal
LABEL maintainer "Red Hat OpenShift Dedicated SRE Team"

RUN microdnf install -y python3 python3-pip
RUN pip3 install pylint

RUN mkdir /app
WORKDIR /app

COPY . ./

RUN pip3 install -r requirements.txt

# W1202: False positive with python3 f-strings
# W0511: Ignore TODO notes
# W0707: Temporarily ignore bare exception warning
# R0911, R0913, R0914, $0915: Temporarily ignore warnings of
# function with too many statements, arguments, returns and variables
RUN pylint -d W0621 \
           -d W0707 \
           -d W1202 \
           -d W1203 \
           -d C0103 \
           -d C0301 \
           -d R0911 \
           -d R0913 \
           -d R0914 \
           -d R0915 \
           curator.py

RUN python3 -m unittest test_curator.py

ENTRYPOINT ["/app/curator.py"]
CMD ["--skip-push"]

