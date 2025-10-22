# Use the official Python 3.10 image
FROM python:3.10-buster

# Install dependencies
ENV WORKSPACE_BASE_PATH="/workspace/monitoring"

COPY ../private_key /workspace/monitoring/private_key
RUN chmod 600 /workspace/monitoring/private_key
RUN echo "eval \$(ssh-agent -s)" >> /etc/bash.bashrc && \
    echo "ssh-add /workspace/monitoring/private_key" >> /etc/bash.bashrc

RUN curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | bash
RUN apt-get install git-lfs

RUN git config --global user.email "alain.seys@outlook.com"
RUN git config --global user.name "Alain Seys"

# Install PIP requirements


# Optional: If you need to install Python packages here, uncomment the following lines
 COPY requirements.txt /workspace/monitoring/requirements.txt
 RUN pip install -r /workspace/monitoring/requirements.txt

 RUN git config --global http.sslverify false
