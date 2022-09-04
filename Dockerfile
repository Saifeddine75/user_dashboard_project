FROM python:3
# Allow real time for python output (stdin and stdout)
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
COPY . /user_dashboard_project
EXPOSE 8000