# Use ubuntu:20.04 as the latest LTS with all common functionality
FROM ubuntu:20.04

# Set the working directory
WORKDIR /usr/local/bin/granef

# Copy the current directory contents into the container at working directory
COPY . /usr/local/bin/granef

# Install Python
RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --yes python3-minimal python3-pip dma wget gnupg \
	&& pip3 install --trusted-host pypi.python.org --no-cache-dir -r requirements.txt \
	&& apt-get update \
	&& apt-get purge --yes python3-pip dma wget gnupg \
	&& apt-get autoremove --yes


# Run service_arg_handler.py with arguments when container launches (CMD if there are no arguments) 
ENTRYPOINT ["python3", "API/main.py"]
