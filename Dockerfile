FROM python:3.9-buster

# Set working directory
WORKDIR /app
COPY checkdmarc.py .
COPY requirements.txt .

# Install any necessary dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get -y install cron

RUN echo > /var/log/cron.log
RUN echo "0 * * * * /usr/local/bin/python /app/checkdmarc.py >> /var/log/cron.log 2>&1" | crontab -

# Run the command on container startup
CMD cron && tail -f /var/log/cron.log
