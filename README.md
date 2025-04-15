# Steganography Web Service

A web application that allows users to hide secret messages within files using bit-level steganography.

## Features

- User authentication system
- Hide messages in any file format (images, audio, documents, etc.)
- Customizable steganography parameters:
  - Start bit (S): Skip S bits at the beginning of the carrier file
  - Periodicity (L): Every Lth bit will be modified to store the secret message
  - Mode (C): How L changes during encoding (constant, alternating, increasing, fibonacci)
- Extract hidden messages using the same parameters
- Public gallery of steganography posts
- File upload and download functionality

## Implementation Details

### Steganography Algorithm

The steganography implementation uses bit-level modification to hide messages in files:

1. The message file is read as binary data
2. The size of the message (in bits) is prepended to the message data (32 bits)
3. The carrier file is read as binary data
4. Beginning from the specified start bit (S), every Lth bit of the carrier file is replaced with a bit from the message
5. The modified carrier file is saved, preserving the original format

The periodicity (L) can vary according to the chosen mode:
- **Constant**: L remains the same throughout (e.g., L=8)
- **Alternating**: L alternates between L and 2L (e.g., 8, 16, 8, 16...)
- **Increasing**: L increases by 4 each time, resets after L+20 (e.g., 8, 12, 16, 20, 24, 28, 8...)
- **Fibonacci**: L follows the Fibonacci sequence starting with L (e.g., 8, 8, 16, 24, 40, 64...)

Message extraction reverses this process using the same parameters.

## Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/stegoweb.git
cd stegoweb
```

2. Create a virtual environment and activate it:
```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```
pip install -r requirements.txt
```

4. Run the application:
```
python app.py
```

5. Access the application in your web browser at `http://127.0.0.1:5000`

## Default Admin Account

The application creates a default admin account on first run:
- Username: admin
- Password: admin

**Important:** Change the default admin password immediately after first login for security reasons.

## Project Structure

- `app.py`: Main application file with Flask routes and steganography functions
- `templates/`: HTML templates for the web interface
- `uploads/`: Directory for uploaded and processed files
- `requirements.txt`: List of required Python packages

## Security Notes

- All user passwords are hashed before storage
- Files are stored securely with unique identifiers
- For production deployment, additional security measures should be implemented:
  - Use HTTPS
  - Configure proper session management
  - Set up database backups
  - Implement rate limiting
  - Consider using a production-ready web server like Gunicorn with Nginx

## Deployment Options

For deploying this application, you have several options:

1. **UTA.Cloud**: Contact UTA OIT for hosting options
2. **Microsoft Azure**: Available for free through UTA
3. **AWS Free Tier**: Amazon Web Services offers a free tier for students
4. **Heroku**: Offers a free tier for small applications
5. **PythonAnywhere**: Specialized in Python web applications

## Understanding Steganography Security

The security of this steganography implementation depends on:

1. **Knowledge of the parameters**: Without knowing the correct S, L, and C values, extracting the hidden message is challenging
2. **Statistical analysis resistance**: By using variable bit positions (especially with non-constant modes), the steganography is more resistant to statistical analysis
3. **Format preservation**: Starting after S bits helps preserve the file format headers, making the modified file look normal

However, it's important to note that this is not a cryptographically secure method by itself. For maximum security, it's recommended to encrypt the message before hiding it.
