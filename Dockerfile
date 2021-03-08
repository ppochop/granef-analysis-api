# Use Python alpine as the smallest Python image
FROM python:3.9-slim

# Set the working directory
WORKDIR /usr/local/bin/granef

# Copy the current directory contents into the container at working directory
COPY . /usr/local/bin/granef

# Install Python
RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --yes graphviz graphviz-dev build-essential gcc \
	&& pip3 install --trusted-host pypi.python.org --no-cache-dir -r requirements.txt \
	&& apt-get purge --yes graphviz-dev build-essential gcc \
	&& apt-get autoremove --yes
	

# Run service_arg_handler.py with arguments when container launches (CMD if there are no arguments) 
ENTRYPOINT ["python3", "GranefAPI/main.py"]
