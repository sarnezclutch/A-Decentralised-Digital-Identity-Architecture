# code_base has all the dependencies installed
FROM code_latest

# Set the working directory to /app
WORKDIR /user

# Copy the current directory contents into the container at /app
ADD . ./

# run the command to start uWSGI
#CMD ["waitress-serve", "--port=5002" ,"--call", "cp:create_app"]

# Run flask in dev mode
RUN export FLASK_APP=app.py

CMD ["flask", "run", "--host=0.0.0.0"]
