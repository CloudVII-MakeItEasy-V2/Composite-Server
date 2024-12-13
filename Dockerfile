# Use the official Python image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Then copy the rest of the app
COPY . .


# Expose port 8080 (required by App Engine)
EXPOSE 8080

# Run the application using Gunicorn
CMD ["gunicorn", "-b", "0.0.0.0:8080", "main:app"]