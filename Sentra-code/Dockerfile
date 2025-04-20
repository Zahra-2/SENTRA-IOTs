# Use the official Python image from Docker Hub
FROM alpine

# Set the working directory inside the container
WORKDIR /app

RUN apk update && \
    apk add nmap && \
    apk add nmap-scripts && \
    apk add python3 && \
    apk add py3-pip
    #rm -rf /var/lib/apt/lists/*

# Copy the requirements.txt file and install dependencies
COPY requirements.txt /app/

RUN python3 -m venv env && \
    ./env/bin/pip3 install -r requirements.txt && \
    # this to comment the "codeset" keyword argument from the language model in wapiti package
    # it crashes wapiti when left used on alpine linux
    sed -i "s/codeset/#codeset/" env/lib/python3.12/site-packages/wapitiCore/language/language.py


# Copy the FastAPI app
COPY . /app/

# Expose port 8080 for Cloud Run
EXPOSE 8080

# Command to run the FastAPI app with Uvicorn
CMD ["./env/bin/uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
