# Base Image
FROM python:3.13-slim

WORKDIR /app

# Add pip install if I add third party libraries

COPY . .
# Change this to run using arguments (Default: Running on all interfaces and all ports) Example: CMD ["python3", "main.py", "-p21"]
# See main.py --help for usage
CMD ["python3", "main.py"]

