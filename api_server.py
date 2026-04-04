from config import settings
from main import create_api_app


app = create_api_app()


if __name__ == "__main__":
    app.run(host=settings.host, port=settings.port, debug=settings.debug)
