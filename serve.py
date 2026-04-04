from waitress import serve

from config import settings
from main import create_app


app = create_app()


if __name__ == "__main__":
    serve(app, host=settings.host, port=settings.port, threads=settings.waitress_threads)
