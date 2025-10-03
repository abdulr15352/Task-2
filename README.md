Task 2 for Abdul-Rafeh Alvi with email abal015@student.kristiania.no


You need to make a .env file with the following environment variables:

JWT_SECRET_KEY=choose a secret key for your application to encrypt and decrypt the JWT token

JWT_ALGORITHM=select an algorithm, i used HS256

JWT_EXPIRATION_MINUTES=how long the JWT token remains valid (in minutes)

# How to run the app
## To build the image using Docker run the command:

- docker compose build

## To run the app with Docker run the command:
- docker compose up

## To stop the app from using Docker run the command:
- docker compose down

## If you also want to empty the databases:
- docker compose down -v


## Objectives
- Understand cloud computing fundamentals
- Explore endpoint management strategies
- Implement security best practices
