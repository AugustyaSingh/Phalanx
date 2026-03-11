# Start with a lightweight Python 3.12 environment
FROM python:3.12-slim

# Set the working folder inside the container
WORKDIR /app

# Copy your app.py file into the container
COPY app.py .

# Install the required libraries
# Install the required libraries
RUN pip install --no-cache-dir streamlit playwright python-whois
# Install the browser that Playwright needs to take screenshots
RUN playwright install --with-deps chromium

# Expose the port that Streamlit uses
EXPOSE 8501

# The command that runs when the container starts
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]