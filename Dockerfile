#
# Granef -- graph-based network forensics toolkit
# Copyright (C) 2019-2021  Milan Cermak, Institute of Computer Science of Masaryk University
# Copyright (C) 2020-2021  Denisa Sramkova, Institute of Computer Science of Masaryk University
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#


# Use Python alpine as the smallest Python image
FROM python:3.9-alpine

# Set the working directory
WORKDIR /usr/local/bin/granef

# Copy the current directory contents into the container at working directory
COPY . /usr/local/bin/granef

# Install Python
RUN apk add --update --no-cache py3-grpcio \
	&& pip3 install --trusted-host pypi.python.org --no-cache-dir -r requirements.txt
	
# Run service_arg_handler.py with arguments when container launches (CMD if there are no arguments) 
ENTRYPOINT ["python3", "GranefAPI/main.py"]
